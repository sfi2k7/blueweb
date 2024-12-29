package blueweb

type user struct {
	IsAuthenticated bool
	Username        string
	Email           string
	UserData        interface{}
}
