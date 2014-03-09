package rbac_test

import (
	"testing"

	"github.com/juju/affinity/rbac"
)

/*
 * Permissions:
 * ============
 * Define the fine-grained permissions that will govern access to
 * the various operations of your service.
 */

// ReadPerm is permission to read the board messages
var ReadPerm rbac.Permission = rbac.NewPermission("read-msg")

// ListPerm is permission to list the recent board threads
var ListPerm rbac.Permission = rbac.NewPermission("list-threads")

// PostPerm is permission to post to the board
var PostPerm rbac.Permission = rbac.NewPermission("post-msg")

// StickyPerm is permission to sticky threads.
var StickyPerm rbac.Permission = rbac.NewPermission("sticky-thread")

// DeletePerm is permission to delete threads.
var DeletePerm rbac.Permission = rbac.NewPermission("delete-thread")

// BanPerm is permission to ban users for some period of time.
var BanPerm rbac.Permission = rbac.NewPermission("ban-user")

func ExamplePermission(t *testing.T) {}
