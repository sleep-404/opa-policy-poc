package app.poc
import future.keywords.in

default allow = false

default organizer := false
default speaker := false
default event_user := false
default is_owner := false

has_key(x, k) { _ = x[k] }


user_data := data.users[input.headers.authorization.user_id]

default entity_id := 0
entity_id := input.path[1] if {input.path[1]}

default broadcast_id := 0
broadcast_id := input.body.broadcast_id if {input.body.broadcast_id}
broadcast_id := data.text_qna[entity_id].broadcast_id if {entity_id != 0}


broadcast_data := data.broadcast[broadcast_id]
event_data := data.event[broadcast_data.event_id]


delete_permissions := [organizer, speaker, is_owner]
create_permissions := [organizer, speaker]
get_permissions := [organizer, speaker, event_user]

organizer {
	organization := input.organization_id
	user := input.user_id
	
	data.organizations[organization_id].members[user_id].active == true
}

speaker {
	has_key(broadcast_data.speakers, input.headers.authorization.user_id)
}

event_user {
	user_id := input.user_id
	event_id := input.event_id
	data.events[event_id].members[user_id].blocked == false
}

is_owner {
	data.text_qna[entity_id].owner == input.headers.authorization.user_id
}

has_create_permissions {
	some has_permission in create_permissions
	has_permission
}

has_delete_permissions {
	some has_permission in delete_permissions
	has_permission
}

has_get_permissions {
	some has_permission in get_permissions
	has_permission
}


allow {
	input.action == "CREATE"
	input.path == ["text_qna"]
	has_create_permissions
}

allow {
	input.action == "GET"
	input.path == ["text_qna"]
	has_get_permissions
}

allow {
	input.action == "DELETE"
	input.path[0] == "text_qna"
	count(input.path) == 2
	has_delete_permissions
}
