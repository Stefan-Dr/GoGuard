package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/denisenkom/go-mssqldb"
)

func ConnectDB(username string, password string, serverName string, database string) (*sql.DB, error) {
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

func AddLicence(db *sql.DB, licence string, uid string) (int64, error) {
	now := time.Now()

	query := `
        INSERT INTO dbo.Devices (Uid, LicenceKey, DateTime)
        OUTPUT INSERTED.Id
        VALUES (@Uid, @LicenceKey, @DateTime);
    `
	var id int64
	err := db.QueryRow(
		query,
		sql.Named("Uid", uid),
		sql.Named("LicenceKey", licence),
		sql.Named("DateTime", now),
	).Scan(&id)

	if err != nil {
		return 0, fmt.Errorf("AddLicence : %v", err)
	}
	return id, nil
}
