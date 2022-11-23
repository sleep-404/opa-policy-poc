package app.poc
default allow = false

allow {
	user_is_admin
}

allow {
	some permission
	user_is_granted[permission]
	input.action == permission.action
	input.type == permission.type
	country := data.users[input.user].location.country
	country == "US"
}

user_is_admin {
	input.email == "admin@goldcast.io"
}

