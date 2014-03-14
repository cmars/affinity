package mongo_test

import (
	stdtesting "testing"

	"labix.org/v2/mgo"
	. "launchpad.net/gocheck"
	juju_testing "launchpad.net/juju-core/testing"

	"github.com/juju/affinity/storage/mongo"
	testing "github.com/juju/affinity/testing"
)

type MongoSuite struct {
	*testing.StoreSuite
	*testing.RbacSuite
	Session *mgo.Session
}

func Test(t *stdtesting.T) { TestingT(t) }

var _ = Suite(&MongoSuite{})

func (s *MongoSuite) SetUpSuite(c *C) {
	juju_testing.MgoServer.Start(true)
}

func (s *MongoSuite) TearDownSuite(c *C) {
	juju_testing.MgoServer.Destroy()
}

func (s *MongoSuite) reset() {
	session := juju_testing.MgoServer.MustDial()
	defer session.Close()
	session.DB("affinity_rbac_suite").DropDatabase()
	session.DB("affinity_store_suite").DropDatabase()
}

func (s *MongoSuite) SetUpTest(c *C) {
	s.reset()
	s.Session = juju_testing.MgoServer.MustDial()
	{
		store, err := mongo.NewMongoStore(s.Session, "affinity_store_suite", "", "")
		c.Assert(err, IsNil)
		s.StoreSuite = testing.NewStoreSuite(store)
		s.StoreTests.SetUp(c)
	}
	{
		store, err := mongo.NewMongoStore(s.Session, "affinity_rbac_suite", "", "")
		c.Assert(err, IsNil)
		s.RbacSuite = testing.NewRbacSuite(store)
		s.RbacTests.SetUp(c)
	}
}

func (s *MongoSuite) TearDownTest(c *C) {
	s.Session.Close()
}
