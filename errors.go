package c_polygonid

import (
	"errors"
	"fmt"
)

type ErrCredentialStatus struct {
	err   error
	owner CredentialStatusOwner
}

func (c ErrCredentialStatus) Error() string {
	return fmt.Sprintf("credential status error: %v", c.err)
}

func (c ErrCredentialStatus) Unwrap() error {
	return c.err
}

func (c ErrCredentialStatus) Owner() CredentialStatusOwner {
	return c.owner
}

type ErrCredentialStatusResolve struct {
	err error
}

func (e ErrCredentialStatusResolve) Error() string {
	return fmt.Sprintf("credential status resolve error: %v", e.err)
}

func (e ErrCredentialStatusResolve) Unwrap() error {
	return e.err
}

type ErrCredentialStatusExtract struct {
	err error
}

func (e ErrCredentialStatusExtract) Error() string {
	return fmt.Sprintf(
		"error extracting credential status from verifiable credential: %v",
		e.err)
}

func (e ErrCredentialStatusExtract) Unwrap() error {
	return e.err
}

type ErrCredentialStatusTreeBuild struct {
	err error
}

func (e ErrCredentialStatusTreeBuild) Error() string {
	return fmt.Sprintf(
		"error building tree proof from credential status: %v",
		e.err)
}

func (e ErrCredentialStatusTreeBuild) Unwrap() error {
	return e.err
}

type ErrCredentialStatusTreeState struct {
	msg string
	err error
}

func (e ErrCredentialStatusTreeState) Error() string {
	m := "error validating credential status merkletree proof: " + e.msg
	if e.err != nil {
		m += ": " + e.err.Error()
	}
	return m
}

func (e ErrCredentialStatusTreeState) Unwrap() error {
	return e.err
}

var ErrCredentialStatusRevoked = errors.New("credential is revoked")
