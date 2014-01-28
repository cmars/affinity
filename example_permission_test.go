package affinity_test

import (
	"testing"

	. "launchpad.net/go-affinity"
)

/*
 * Permissions:
 * ============
 * Define the fine-grained permissions that will govern access to
 * the various operations of your service.
 */

// ReadPerm is permission to read the board messages
var ReadPerm Permission = NewPermission("read-msg")

// ListPerm is permission to list the recent board threads
var ListPerm Permission = NewPermission("list-threads")

// PostPerm is permission to post to the board
var PostPerm Permission = NewPermission("post-msg")

// StickyPerm is permission to sticky threads.
var StickyPerm Permission = NewPermission("sticky-thread")

// DeletePerm is permission to delete threads.
var DeletePerm Permission = NewPermission("delete-thread")

// BanPerm is permission to ban users for some period of time.
var BanPerm Permission = NewPermission("ban-user")

func ExamplePermission(t *testing.T) {}
