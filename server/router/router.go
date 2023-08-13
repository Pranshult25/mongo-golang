package router

import (
	"context"
	"fmt"
	"log"

	// "net/http"
	"regexp"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt"
	"github.com/pranshult25/queriesportalbackend/common"
	"github.com/pranshult25/queriesportalbackend/models"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/mgo.v2/bson"
)

var tokenString = makeToken()
const secret = "secret123"


func Router(app *fiber.App){
	router := app.Group("/")
    
    // router.HandleFunc("/", controllers.Home).Methods("GET")
    // router.HandleFunc("/register", controllers.Register).Methods("POST")
    // router.HandleFunc("/user", controllers.User).Methods("GET")
    // router.HandleFunc("/login", controllers.Login).Methods("POST")
    // router.HandleFunc("/logout", controllers.Logout).Methods("POST")
    // router.HandleFunc("/comments", controllers.FindComments).Methods("GET")
    // router.HandleFunc("/comments/root/{rootId}", controllers.FindCommentsByRootId).Methods("GET")
    // router.HandleFunc("/comments/{id}", controllers.FindCommentsById).Methods("GET")
    // router.HandleFunc("/comments", controllers.PostComments).Methods("POST")

    router.Get("/", home)
    router.Post("/register", insertOneUser)
    router.Get("/user", findusers)
    router.Post("/login", login)
    router.Post("/logout", logout)
    router.Get("/comments", getComments)
    router.Get("/comments/root/:rootId", getCommentByRootId)
    router.Get("comments/:id", getCommentsById)
    router.Post("/comments", postComments)

}
type test_user struct {
    id int
    username string
    role string
}
func makeToken() (tokenString string){
	user := test_user{
        id: 123,
        username: "exampleuser",
        role: "user",
    }


	claims := jwt.MapClaims{
		"user": &user,
		"exp": time.Now().Add(time.Hour*1).Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err  := token.SignedString([]byte(secret))

	if err != nil{
		log.Fatal(err)
	}
    
	fmt.Println("JWT", tokenString)

	return tokenString
}

func checkEmail(email string) bool{
    Re := regexp.MustCompile(`[a-z0-9._%+\-]+@[a-z0-9._%+\-]+\.[a-z0-9._%+\-]`)
	return Re.MatchString(email)
}

func getUserFromToken(tokenString string) (*models.User, error){
    coll := common.GetDBCollection("Users")

	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		log.Fatal(err)
	}

	var user models.User

	userID := claims["id"].(string)
	filter := bson.M{"_id": userID}

    err = coll.FindOne(context.Background(), filter).Decode(user)

	if err != nil{
		log.Fatal(err)
	}

	return &user, nil
}

//Ok
func home(c *fiber.Ctx) error{
    return c.Status(200).JSON(fiber.Map{
        "status": "Connected",
    })
    
}

//OK
func insertOneUser(c *fiber.Ctx) error{
	user := new(models.User)
	if err := c.BodyParser(user); err != nil {
        return c.Status(400).JSON(fiber.Map{
            "error": "Invalid body",
        })
	}
    if user.Password != ""{
    bytepassword, _ := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
    user.Password = string(bytepassword)
    }

    if user.Email == "" || user.Username == ""{
        return c.Status(400).JSON(fiber.Map{
            "error": "invalid details",
        })
    }

    if !checkEmail(user.Email) {
        return c.Status(500).JSON(fiber.Map{
            "error": "Enter a valid email-id",
        })
    }

	// create the book
	coll := common.GetDBCollection("Users")
	result, err := coll.InsertOne(c.Context(), user)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   "Failed to create book",
			"message": err.Error(),
		})
	}

	// return the book
    
    var cookie fiber.Cookie
    cookie.Name = "token"
    cookie.Value = tokenString
    cookie.HTTPOnly = true
    cookie.Secure = true
    
    c.Cookie(&cookie)
    

    return c.Status(201).JSON(fiber.Map{
        "result": result,
    })
}

//Ok
func findusers(c *fiber.Ctx) error{
    coll := common.GetDBCollection("Users")

	// find all books
	users := make([]models.User, 0)
	cursor, err := coll.Find(c.Context(), bson.M{})
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error": err.Error(),
		})
	}

	// iterate over the cursor
	for cursor.Next(c.Context()) {
		user := models.User{}
		err := cursor.Decode(&user)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"error": err.Error(),
			})
		}
		users = append(users, user)
	}

	return c.Status(200).JSON(fiber.Map{"data": users})
}

//OK
func login(c *fiber.Ctx) error{
    coll := common.GetDBCollection("Users")
    
    user := new(models.User)
    if err := c.BodyParser(user); err != nil {
        return c.Status(400).JSON(fiber.Map{
            "error": "Invalid body",
        })
    }

    existedUser := models.User{}

    err := coll.FindOne(c.Context(), bson.M{"username": user.Username}).Decode(&existedUser)
    if err != nil{
        return c.Status(500).JSON(fiber.Map{
            "status": "Can't find the user with this username.",
        })
    } 
    
    passOk := bcrypt.CompareHashAndPassword([]byte(existedUser.Password), []byte(user.Password))
    if passOk != nil{
        return c.Status(404).JSON(fiber.Map{
            "status": "Invalid Username or Password",
        })
    } 

    token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
                "id": existedUser.Id,
            })
    tokenString_login, err := token.SignedString([]byte(secret))
    if err != nil{
        return c.Status(400).JSON(fiber.Map{
            "status": "Can't convert to a tokenString",
        })
    }

    var cookie fiber.Cookie
    cookie.Name = "token"
    cookie.Value = tokenString_login
    cookie.HTTPOnly = true
    cookie.Secure = true
    
    c.Cookie(&cookie)

    return c.Status(200).JSON(fiber.Map{
        "status": "Logged-In successfully",
        "data": existedUser,
    }) 
}


func logout(c *fiber.Ctx) error{
    return c.Status(200).JSON(fiber.Map{
        "status": "Successfully logged-out",
    })
}

func getComments(c *fiber.Ctx) error{
    coll := common.GetDBCollection("Comments")

//     search := string(c.Request().URI().QueryString())
//     var filters map[string]interface{}
// 	if search != "" {
// 		filters = map[string]interface{}{
// 			"body": regexp.MustCompile(".*" + search + ".*"),
// 		}
// 	} else {
// 		filters = map[string]interface{}{
// 			"rootId": nil,
// 		}
// }

//     comments, err := coll.Find(c.Context(), filters)
//     if err != nil{
//         return c.Status(500).JSON(fiber.Map{
//             "Status": "No comments were found.",
//         })
//     }

//     return c.Status(200).JSON(fiber.Map{
//         "data" : comments,
//     })

    search := c.Query("search")
    var filters bson.M

    if search != "" {
        searchRegex := primitive.Regex{Pattern: ".*" + escapeRegExp(search) + ".*", Options: "i"}
        filters = bson.M{"body": searchRegex}
    } else {
        filters = bson.M{"Id": nil}
    }

    options := options.Find().SetSort(bson.D{{Name: "postedAt", Value: -1}})
    cur, err := coll.Find(c.Context(), filters, options)
    if err != nil {
        return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
    }
    defer cur.Close(context.Background())

    var comments []models.Comment
    for cur.Next(c.Context()) {
        var comment models.Comment
        err := cur.Decode(&comment)
        if err != nil {
            return c.Status(fiber.StatusInternalServerError).SendString(err.Error())
        }
        comments = append(comments, comment)
    }

    return c.JSON(comments)
    
}

func escapeRegExp(s string) string {
	return regexp.QuoteMeta(s)
}
// func x(w http.ResponseWriter, r *http.Request) {
//     search := r.URL.Query().Get("search")
// }

//Can't insert token
func postComments(c *fiber.Ctx) error{
    tokenString := c.Cookies("token")
    if tokenString == ""{
        return c.Status(fiber.StatusUnauthorized).SendString("Unauthorised")
    }
    userInfo, err := getUserFromToken(string(tokenString))
    if err != nil{
        c.Status(500).JSON(fiber.Map{
            "error": err.Error(),
        })
    }

    coll := common.GetDBCollection("Comments")

    comment := new(models.Comment)
    if err := c.BodyParser(comment); err != nil {
        return c.Status(400).JSON(fiber.Map{
            "error": "Invalid body",
        })
	}

    comment.PostedAt = time.Now()
    comment.Author = userInfo.Username

    _, err = coll.InsertOne(c.Context(), comment)
    if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"error":   "Failed to create comment",
			"message": err.Error(),
		})
	} 

    return c.Status(200).JSON(fiber.Map{
        "data": comment,
    })

}

func getCommentByRootId(c *fiber.Ctx) error{
    coll := common.GetDBCollection("Comments")

    rootId := c.Params("rootId")
    if rootId == ""{
        c.Status(404).JSON(fiber.Map{
            "error": "Please provide an valid root Id",
        })
    }

    id, err := primitive.ObjectIDFromHex(rootId)
    if err != nil{
        c.Status(500).JSON(fiber.Map{
            "Status": "Invalid root id",
        })
    }

    comment := new(models.Comment)

    err = coll.FindOne(c.Context(), bson.M{"rootId": id}).Decode(&comment)
    if err != nil{
        c.Status(404).JSON(fiber.Map{
            "error": "Cannot find an comment with this rootId",
        })
    }

    return c.Status(200).JSON(fiber.Map{
        "data": comment,
    })
}

func getCommentsById(c *fiber.Ctx) error{
    coll := common.GetDBCollection("Comments")

    Id := c.Params("id")
    if Id == ""{
        c.Status(404).JSON(fiber.Map{
            "error": "Please provide an valid root Id",
        })
    }

    ObjectID, err := primitive.ObjectIDFromHex(Id)
    if err != nil{
        c.Status(500).JSON(fiber.Map{
            "Status": "Invalid root id",
        })
    }

    comment := new(models.Comment)

    err = coll.FindOne(c.Context(), bson.M{"_id": ObjectID}).Decode(&comment)
    if err != nil{
        c.Status(404).JSON(fiber.Map{
            "error": "Cannot find an comment with this rootId",
        })
    }

    return c.Status(200).JSON(fiber.Map{
        "data": comment,
    })
}




// func PostComments(w http.ResponseWriter, r *http.Request){
//     tokenString, err := r.Cookie("token")
//     if err != nil || tokenString == nil{
//         w.WriteHeader(http.StatusUnauthorized)
//         return
//     }

//     userInfo, err := getUserFromToken(tokenString.Value)
//     if err != nil{
//         w.WriteHeader(http.StatusUnauthorized)
//         return
//     }

//     var comment models.Comment
//     err = json.NewDecoder(r.Body).Decode(&comment)
//     if err != nil{
//         w.WriteHeader(http.StatusBadRequest)
//         return
//     }

//     comment.Author = userInfo.Username
//     comment.PostedAt = time.Now()

//     insertOneComment(&comment)

//     json.NewEncoder(w).Encode(comment)
// }
// func Logout(w http.ResponseWriter, r *http.Request){
// 	http.SetCookie(w, &http.Cookie{
// 		Name: "token",
// 		Value: "",
// 		HttpOnly: true,
// 		Secure: true,
// 	})
// 	w.WriteHeader(http.StatusOK)
// }

// func FindComments(w http.ResponseWriter, r *http.Request){
// 	result := r.URL.Query().Get("search")
// 	var filters map[string]interface{}

// 	if result != "" {
// 		filters = map[string]interface{}{
// 			"body": regexp.MustCompile(".*" + result + ".*"),
// 		}
// 	} else {
// 		filters = map[string]interface{}{
// 			"rootId": nil,
// 		}
// 	}

// 	var comment models.Comment

// 	err := collection_comments.FindOne(context.TODO(), filters).Decode(&comment)																																			
// 	if err != nil {
//         w.WriteHeader(http.StatusInternalServerError)
// 		w.Write([]byte("Internal server error"))
// 		fmt.Println("Unable to find the comment.")
// 		return
// 	}
// 	json.NewEncoder(w).Encode(comment)
// }

// func FindCommentsByRootId(w http.ResponseWriter, r *http.Request){
// 	params := mux.Vars(r)

// 	rootId := params["rootId"]

// 	var comment models.Comment

// 	err := collection_comments.FindOne(context.TODO(), bson.M{"rootId": rootId}).Decode(&comment)
    
//     if err != nil{
// 		w.WriteHeader(http.StatusInternalServerError)
// 		fmt.Println("The following comment with the rootId doesn't exist.")
// 	}
   
//     json.NewEncoder(w).Encode(comment)
// }

// func FindCommentsById(w http.ResponseWriter, r *http.Request){
// 	params := mux.Vars(r)
    
// 	Id := params["id"]

// 	var comment models.Comment

// 	err := collection_comments.FindOne(context.TODO(), bson.M{"parentId":Id}).Decode(&comment)

// 	if err != nil{
// 		w.WriteHeader(http.StatusInternalServerError)
// 		fmt.Println("The following comment with the Id doesn't exist.")
// 	}

// 	json.NewEncoder(w).Encode(comment)
// }
