package masks

type Masker interface {
	Wrap(payload []byte) []byte
	Unwrap(data []byte) ([]byte, error)
	ID() string
}
