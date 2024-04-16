package suite

type SuiteOptions string

type Role string

const (
	P256 SuiteOptions = "P256"
)

const (
	Server Role = "Server"
	Client Role = "Client"
)

func SelectECCSuite(name SuiteOptions) *Suite {
	switch name {
	case P256:
		return NewP256Suite()
	default:
		return nil
	}
}
