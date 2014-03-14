package db_auth_test

import (
	"fmt"

	stdtesting "testing"

	"labix.org/v2/mgo"
	. "launchpad.net/gocheck"
	juju_testing "launchpad.net/juju-core/testing"

	"github.com/juju/affinity/storage/mongo"
	testing "github.com/juju/affinity/testing"
)

type MongoAuthSuite struct {
	*testing.StoreSuite
	*testing.RbacSuite
	Session *mgo.Session
}

func Test(t *stdtesting.T) { TestingT(t) }

var _ = Suite(&MongoAuthSuite{})

func (s *MongoAuthSuite) SetUpSuite(c *C) {
	juju_testing.MgoServer.Start(true)
}

func (s *MongoAuthSuite) TearDownSuite(c *C) {
	juju_testing.MgoServer.Destroy()
}

func (s *MongoAuthSuite) reset() {
	session := juju_testing.MgoServer.MustDial()
	defer session.Close()
	session.DB("affinity_rbac_suite_auth").DropDatabase()
	session.DB("affinity_store_suite_auth").DropDatabase()
}

func (s *MongoAuthSuite) setPassword() error {
	store := s.Session.DB("affinity_store_suite_auth")
	if err := store.AddUser("admin", "password", false); err != nil && err.Error() != "need to login" {
		return fmt.Errorf("cannot set admin password: %v", err)
	}
	rbac := s.Session.DB("affinity_rbac_suite_auth")
	if err := rbac.AddUser("admin", "password", false); err != nil && err.Error() != "need to login" {
		return fmt.Errorf("cannot set admin password: %v", err)
	}
	return nil
}

func (s *MongoAuthSuite) SetUpTest(c *C) {
	s.reset()
	s.Session = juju_testing.MgoServer.MustDial()
	c.Assert(s.setPassword(), IsNil)
	{
		store, err := mongo.NewMongoStore(s.Session, "affinity_store_suite_auth", "admin", "password")
		c.Assert(err, IsNil)
		s.StoreSuite = testing.NewStoreSuite(store)
		s.StoreTests.SetUp(c)
	}
	{
		store, err := mongo.NewMongoStore(s.Session, "affinity_rbac_suite_auth", "admin", "password")
		c.Assert(err, IsNil)
		s.RbacSuite = testing.NewRbacSuite(store)
		s.RbacTests.SetUp(c)
	}
}

func (s *MongoAuthSuite) TearDownTest(c *C) {
	s.Session.Close()
}
