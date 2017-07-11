package readpwd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/Declan94/cfcryptfs/internal/tlog"

	"golang.org/x/crypto/ssh/terminal"
)

const (
	// 2kB limit like EncFS
	maxPasswordLen = 2048
)

// Once tries to get a password from the user, either from the terminal, extpass
// or stdin.
func Once(extpass string) (string, error) {
	if extpass != "" {
		return readPasswordExtpass(extpass)
	}
	if !terminal.IsTerminal(int(os.Stdin.Fd())) {
		return readPasswordStdin()
	}
	return readPasswordTerminal("Password: ")
}

// Twice is the same as Once but will prompt twice if we get the password from
// the terminal.
func Twice(extpass string) (string, error) {
	if extpass != "" {
		return readPasswordExtpass(extpass)
	}
	if !terminal.IsTerminal(int(os.Stdin.Fd())) {
		return readPasswordStdin()
	}
	p1, err := readPasswordTerminal("Password: ")
	if err != nil {
		return "", err
	}
	p2, err := readPasswordTerminal("Repeat: ")
	if err != nil {
		return "", err
	}
	if p1 != p2 {
		return "", errors.New("Passwords do not match")
	}
	return p1, nil
}

// readPasswordTerminal reads a line from the terminal.
// Exits on read error or empty result.
func readPasswordTerminal(prompt string) (string, error) {
	fd := int(os.Stdin.Fd())
	fmt.Fprintf(os.Stderr, prompt)
	// terminal.ReadPassword removes the trailing newline
	p, err := terminal.ReadPassword(fd)
	if err != nil {
		return "", fmt.Errorf("Could not read password from terminal: %v", err)
	}
	fmt.Fprintf(os.Stderr, "\n")
	if len(p) == 0 {
		return "", errors.New("Password is empty")
	}
	return string(p), nil
}

// readPasswordStdin reads a line from stdin.
// It exits with a fatal error on read error or empty result.
func readPasswordStdin() (string, error) {
	tlog.Info.Println("Reading password from stdin")
	p, err := readLineUnbuffered(os.Stdin)
	if err != nil {
		return "", err
	}
	if len(p) == 0 {
		return "", errors.New("Got empty password from stdin")
	}
	return p, nil
}

// readPasswordExtpass executes the "extpass" program and returns the first line
// of the output.
// Exits on read error or empty result.
func readPasswordExtpass(extpass string) (string, error) {
	tlog.Info.Println("Reading password from extpass program")
	var parts []string
	// The option "-passfile=FILE" gets transformed to
	// "-extpass="/bin/cat -- FILE". We don't want to split FILE on spaces,
	// so let's handle it manually.
	passfileCat := "/bin/cat -- "
	if strings.HasPrefix(extpass, passfileCat) {
		parts = []string{"/bin/cat", "--", extpass[len(passfileCat):]}
	} else {
		parts = strings.Split(extpass, " ")
	}
	cmd := exec.Command(parts[0], parts[1:]...)
	cmd.Stderr = os.Stderr
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("extpass pipe setup failed: %v", err)
	}
	err = cmd.Start()
	if err != nil {
		return "", fmt.Errorf("extpass cmd start failed: %v", err)
	}
	p, err := readLineUnbuffered(pipe)
	if err != nil {
		return "", err
	}
	pipe.Close()
	err = cmd.Wait()
	if err != nil {
		return "", fmt.Errorf("extpass program returned an error: %v", err)

	}
	if len(p) == 0 {
		return "", fmt.Errorf("extpass: password is empty")
	}
	return p, nil
}

// readLineUnbuffered reads single bytes from "r" util it gets "\n" or EOF.
// The returned string does NOT contain the trailing "\n".
func readLineUnbuffered(r io.Reader) (string, error) {
	b := make([]byte, 1)
	var l string
	for {
		if len(l) > maxPasswordLen {
			return "", fmt.Errorf("Maximum password length of %d bytes exceeded", maxPasswordLen)
		}
		n, err := r.Read(b)
		if err == io.EOF {
			return l, nil
		}
		if err != nil {
			return "", fmt.Errorf("readLineUnbuffered: %v", err)
		}
		if n == 0 {
			continue
		}
		if b[0] == '\n' {
			return l, nil
		}
		l = l + string(b)
	}
}
