package mikrotik

type Client struct {
	Address  string
	Username string
	Password string
}

func NewClient(address, username, password string) *Client {
	return &Client{Address: address, Username: username, Password: password}
}

func (c *Client) Apply(script string) error {
	return nil
}
