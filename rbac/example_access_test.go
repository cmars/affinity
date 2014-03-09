package rbac_test

import (
	"fmt"
	"testing"

	. "github.com/juju/affinity"
	"github.com/juju/affinity/rbac"
	"github.com/juju/affinity/storage/mem"
)

// MessageBoard defines the interface for a message board service.
type MessageBoard interface {
	// Lurk fetches a page of posts, by page number, lower = newer.
	Lurk(pageNum int) (string, error)
	// Read fetches a single post content.
	Read(id int) (string, error)
	// Post writes a message to the board, returns its id.
	Post(msg string) (int, error)
	// Sticky prevents the message from rolling off, keeps it at the top.
	Sticky(threadId int) error
	// Ban a user for some time.
	Ban(user User, seconds int) error
	// Delete a message.
	Delete(threadId int) error
}

var MessageBoardRoles rbac.RoleMap = rbac.NewRoleMap(LurkerRole, PosterRole, ModeratorRole)

var AccessDenied error = fmt.Errorf("Access denied")

// MessageBoardResource represents the entire message board.
var MessageBoardResource rbac.Resource = rbac.NewResource("message-board:",
	ReadPerm, ListPerm, PostPerm, DeletePerm, StickyPerm, BanPerm)

// mbConn is a connection to the message board service as a certain user.
type mbConn struct {
	*rbac.Access
	AsUser User
}

func (mb *mbConn) Lurk(pageNumber int) (string, error) {
	// Check that the user has list permissions on the message board
	can, err := mb.Can(mb.AsUser, ListPerm, MessageBoardResource)
	if err != nil {
		return "", err
	}
	if !can {
		return "", AccessDenied
	}
	// Get the page content
	return mb.loadPage(pageNumber)
}

func (mb *mbConn) Post(msg string) (int, error) {
	can, err := mb.Can(mb.AsUser, PostPerm, MessageBoardResource)
	if err != nil {
		return 0, err
	}
	if !can {
		return 0, AccessDenied
	}
	return mb.post(msg)
}

func ExampleAccess(t *testing.T) {
	// Let's set up an RBAC store. We'll use the in-memory store
	// for this example. You should use something more permanent like the Mongo store.
	store := mem.NewStore()
	// Admin lets us grant and revoke roles
	admin := rbac.NewAdmin(store, MessageBoardRoles)
	// Anonymous scheme users can lurk and that's all
	admin.Grant(User{Identity: Identity{"anon", "*"}}, LurkerRole, MessageBoardResource)
	// Verified Gooble users can post
	admin.Grant(User{Identity: Identity{"gooble", "*"}}, PosterRole, MessageBoardResource)

	// A wild anon appears
	anon := User{Identity: Identity{"anon", "10.55.61.128"}}

	// Connect to the message board service as this user
	// In a web application, you'll likely derive the user from http.Request, using
	// OAuth, OpenID, cookies, etc.
	mb := &mbConn{&rbac.Access{store, MessageBoardRoles}, anon}

	// Print the first page of the message board. The MessageBoard will check
	// Access.Can(user, ListPerm, MessageBoardResource).
	content, err := mb.Lurk(0)
	if err != nil {
		panic(err)
	}
	fmt.Println(content)

	// A tame authenticated user appears. Reattach as tame user now.
	// In real life, this would likely be in a distinct http.Handler with its own session.
	tame := User{Identity: Identity{"gooble", "YourRealName"}}
	mb = &mbConn{&rbac.Access{store, MessageBoardRoles}, tame}

	// Post a message.
	_, err = mb.Post("check 'em")
	if err != nil {
		panic(err)
	}
}
