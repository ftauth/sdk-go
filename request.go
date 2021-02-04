package ftauth

// Request holds an HTTP request and metadata.
type Request struct {
	Method string
	URL    string
	Body   []byte
	Public bool
}
