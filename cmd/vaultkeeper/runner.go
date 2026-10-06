package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/afterdarksys/secretserver-autohsm/internal/ceremony"
)

// Runner triggers node-side autohsm commands. vaultkeeper never reaches a
// node itself: the operator's approval-gated fleet runner does, and each
// command is a fixed string an exact-command runbook can allowlist.
type Runner interface {
	// Contribute runs `autohsm contribute <op>` on node. It returns the
	// node's stdout when the runner can capture it, or nil when it cannot;
	// vaultkeeper then follows progress on Vault instead.
	Contribute(ctx context.Context, node Node, op string) ([]byte, error)
	// Wrap pipes share to `autohsm wrap --index N --install` on node over
	// stdin. Runners that cannot pipe return errCannotPipe.
	Wrap(ctx context.Context, node Node, share []byte) error
	// Selftest runs `autohsm selftest` on node.
	Selftest(ctx context.Context, node Node) error
	// CanPipe reports whether Wrap and Selftest are supported.
	CanPipe() bool
}

// resultPrompter is implemented by runners that cannot capture node output:
// the operator pastes the completing node's result line. The raw text is
// returned unparsed so that nothing is lost if it does not parse.
type resultPrompter interface {
	PromptResult(ctx context.Context, node Node, op string) ([]byte, error)
}

var errCannotPipe = errors.New("the manual runner cannot pipe a share to a node; configure runner.exec")

func contributeArgs(op string) []string { return []string{"autohsm", "contribute", op} }

func wrapArgs(node Node) []string {
	return []string{"autohsm", "wrap", "--index", strconv.Itoa(node.ShareIndex), "--install"}
}

func selftestArgs() []string { return []string{"autohsm", "selftest"} }

// maxRunnerOutput bounds what vaultkeeper keeps of one runner invocation.
const maxRunnerOutput = 2 * ceremony.MaxResultLine

// ManualRunner is the default. It prints the exact command the operator's
// runner must execute on each node and lets vaultkeeper poll Vault for the
// resulting progress. It never contacts a node.
type ManualRunner struct {
	Out      io.Writer
	In       io.Reader
	Approval string
}

func (m *ManualRunner) Contribute(_ context.Context, node Node, op string) ([]byte, error) {
	fmt.Fprintf(m.Out, "\n[vaultkeeper] on %s, run through the approval-gated runner (approval contract %s):\n\n    %s\n\n[vaultkeeper] waiting for Vault progress...\n",
		node.Name, m.Approval, strings.Join(contributeArgs(op), " "))
	return nil, nil
}

func (m *ManualRunner) PromptResult(ctx context.Context, node Node, op string) ([]byte, error) {
	fmt.Fprintf(m.Out, "[vaultkeeper] the %s attempt completed. Paste the single %q line %s printed (it is PGP-encrypted):\n",
		op, strings.TrimSpace(ceremony.ResultPrefix), node.Name)
	type lineErr struct {
		line string
		err  error
	}
	ch := make(chan lineErr, 1)
	go func() {
		// Bounded: a pasted line can never grow without limit.
		r := bufio.NewReader(io.LimitReader(m.In, ceremony.MaxResultLine+2))
		line, err := r.ReadString('\n')
		ch <- lineErr{line, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case le := <-ch:
		if le.err != nil && le.line == "" {
			return nil, fmt.Errorf("read result line: %w", le.err)
		}
		return []byte(le.line), nil
	}
}

func (m *ManualRunner) Wrap(context.Context, Node, []byte) error { return errCannotPipe }
func (m *ManualRunner) Selftest(context.Context, Node) error     { return errCannotPipe }
func (m *ManualRunner) CanPipe() bool                            { return false }

// ExecRunner runs the operator's fleet runner binary directly (no shell):
// Argv with {node} and {approval} substituted, then the node command.
type ExecRunner struct {
	Argv     []string
	Approval string
	// Timeout bounds one invocation; the process is killed when it expires.
	Timeout time.Duration
	// Stderr receives the runner's and node's diagnostics (never secrets:
	// autohsm prints no share, and the share goes over stdin only).
	Stderr io.Writer
}

func (r *ExecRunner) argv(node Node, cmd []string) []string {
	out := make([]string, 0, len(r.Argv)+len(cmd))
	for _, a := range r.Argv {
		a = strings.ReplaceAll(a, "{node}", node.Name)
		a = strings.ReplaceAll(a, "{approval}", r.Approval)
		out = append(out, a)
	}
	return append(out, cmd...)
}

// cappedBuffer keeps at most max bytes and records overflow.
type cappedBuffer struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	if room := c.max - c.buf.Len(); len(p) > room {
		c.overflow = true
		if room > 0 {
			c.buf.Write(p[:room])
		}
		return len(p), nil
	}
	return c.buf.Write(p)
}

func (r *ExecRunner) run(ctx context.Context, node Node, cmdArgs []string, stdin []byte) ([]byte, error) {
	if r.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, r.Timeout)
		defer cancel()
	}
	argv := r.argv(node, cmdArgs)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// After the kill, give up on pipes a stray grandchild still holds.
	cmd.WaitDelay = 5 * time.Second
	cmd.Stderr = r.Stderr
	out := &cappedBuffer{max: maxRunnerOutput}
	cmd.Stdout = out
	var in io.WriteCloser
	var err error
	if stdin != nil {
		if in, err = cmd.StdinPipe(); err != nil {
			return nil, err
		}
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start runner for %s: %w", node.Name, err)
	}
	werr := make(chan error, 1)
	if in != nil {
		// Written straight into the pipe: no intermediate copy of the share.
		go func() {
			_, e := in.Write(stdin)
			if e == nil {
				_, e = in.Write([]byte("\n"))
			}
			if cerr := in.Close(); e == nil {
				e = cerr
			}
			werr <- e
		}()
	} else {
		werr <- nil
	}
	waitErr := cmd.Wait()
	if e := <-werr; e != nil && waitErr == nil {
		waitErr = fmt.Errorf("write stdin: %w", e)
	}
	captured := out.buf.Bytes()
	if waitErr != nil {
		if ctx.Err() == context.DeadlineExceeded {
			waitErr = fmt.Errorf("timed out after %s: %w", r.Timeout, waitErr)
		}
		return captured, fmt.Errorf("%s on %s: %w", strings.Join(cmdArgs, " "), node.Name, waitErr)
	}
	if out.overflow {
		return captured, fmt.Errorf("%s on %s: output exceeds %d bytes", strings.Join(cmdArgs, " "), node.Name, maxRunnerOutput)
	}
	return captured, nil
}

func (r *ExecRunner) Contribute(ctx context.Context, node Node, op string) ([]byte, error) {
	out, err := r.run(ctx, node, contributeArgs(op), nil)
	if out == nil {
		out = []byte{}
	}
	return out, err
}

func (r *ExecRunner) Wrap(ctx context.Context, node Node, share []byte) error {
	_, err := r.run(ctx, node, wrapArgs(node), share)
	return err
}

func (r *ExecRunner) Selftest(ctx context.Context, node Node) error {
	_, err := r.run(ctx, node, selftestArgs(), nil)
	return err
}

func (r *ExecRunner) CanPipe() bool { return true }
