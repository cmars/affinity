package affinity_test

import (
	"testing"

	. "github.com/juju/affinity"
)

/*
 * Roles:
 * ======
 * Define the roles defining the different levels of access for the
 * users of your service.
 */

// LurkerRole is someone who can only read the posts.
var LurkerRole Role = NewRole("lurker", ReadPerm, ListPerm)

// PosterRole is someone who can post refreshing, original content.
var PosterRole Role = NewRole("poster", ReadPerm, ListPerm, PostPerm)

// ModeratorRole is someone who can delete posts and ban users.
var ModeratorRole Role = NewRole("moderator",
	ReadPerm, ListPerm, PostPerm,
	StickyPerm, DeletePerm, BanPerm)

func ExampleRole(t *testing.T) {
	// Lurkers can read and list messages, but that's all
	LurkerRole.Can(ReadPerm) // == true
	LurkerRole.Can(ListPerm) // == true
	LurkerRole.Can(PostPerm) // == false
	LurkerRole.Can(BanPerm)  // == false

	// Posters can post messages too, but can't moderate
	PosterRole.Can(ReadPerm)   // == true
	PosterRole.Can(PostPerm)   // == true
	PosterRole.Can(DeletePerm) // == false

	// Mods can moderate too
	ModeratorRole.Can(ReadPerm) // == true
	ModeratorRole.Can(ListPerm) // == true
	ModeratorRole.Can(PostPerm) // == true
	ModeratorRole.Can(BanPerm)  // == true
}
