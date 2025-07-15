package db

import (
	"database/sql"
	"fmt"

	_ "github.com/denisenkom/go-mssqldb"
)

func ConnectDB(username string, password string, serverName string, database string) (*sql.DB, error) {
	// parts := strings.Split(serverName, `\`)
	// connString := fmt.Sprintf(
	// 	"sqlserver://%s:%s@%s:1433?database=%s&encrypt=true&trustservercertificate=true",
	// 	username, password, parts[0], database,
	// )
	connString := fmt.Sprintf("server=%s;user id=%s;password=%s;database=%s;encrypt=true;trustservercertificate=true",
		serverName, username, password, database)

	db, err := sql.Open("sqlserver", connString)
	if err != nil {
		return nil, err
	}
	fmt.Println("db connected successfully")

	err = db.Ping()
	if err != nil {
		return nil, err
	}
	fmt.Println("db ping successful")

	return db, nil
}
