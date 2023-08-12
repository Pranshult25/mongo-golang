package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type Comment struct {
	Author   string              `json:"author,omitempty" bson:"author,omitempty"`
	Title    string              `json:"title" bson:"title"`
	Body     string              `json:"body" bson:"body"`
	PostedAt time.Time           `json:"postedAt,omitempty" bson:"postedAt,omitempty"`
	ParentId primitive.ObjectID  `json:"parentId,omitempty" bson:"parentId,omitempty"`
	RootId   primitive.ObjectID  `json:"rootId,omitempty" bson:"rootId,omitempty"`
}