## example

```GO
	router := blueweb.NewRouter()

	router.Ws("/ws/:token", func(c *blueweb.WSArgs) blueweb.WsData {
		if c.EventType == blueweb.WsEventOpen {
			return c.Body
		}

		if c.EventType == blueweb.WsEventError {
		}

		if c.EventType == blueweb.WsEventClose {
			c.Broadcase(blueweb.WsData{"msg": "so long"})
		}

		if c.EventType == blueweb.WsEventMessage {
		}

		return nil
	})

	//this will run first
	router.Use(func(c *blueweb.Context) bool {
		c.Set("user", "User1")
		return true
	})

	//this will run second
	router.Get("/", func(c *blueweb.Context) {
		c.View("./index.html", blueweb.O{"user": c.Get("user")})
	})

	//this will run last
	router.Must(func(c *blueweb.Context) bool {
		c.Del("user")
		return true
	})

	config := router.Config().StopOnInterrupt().SetDev(true)
	config.SetStatsEndpoint("/stats/:token").SetStatsToken("123456")

	router.StartServer()
```