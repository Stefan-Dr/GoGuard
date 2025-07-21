package db

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/Stefan-Dr/GoGuard/models"
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

func AddLicence(db *sql.DB, hwid string, licence string, uid string) (int64, error) {
	now := time.Now()

	query := `
        UPDATE dbo.Devices
        SET Uid = @Uid, LicenceKey = @LicenceKey, DateTime = @DateTime
        OUTPUT INSERTED.Id
        WHERE Hwid = @Hwid;
    `
	var id int64
	err := db.QueryRow(
		query,
		sql.Named("Uid", uid),
		sql.Named("LicenceKey", licence),
		sql.Named("DateTime", now),
		sql.Named("Hwid", hwid),
	).Scan(&id)

	if err != nil {
		fmt.Printf("AddLicence : %v", err)
		return 0, err
	}
	return id, nil
}

func GetDeviceByHwid(db *sql.DB, hwid string) (*models.Device, error) {
	query := `
        SELECT Id, Hwid, Uid, LicenceKey, DateTime
        FROM dbo.Devices
        WHERE Hwid = @Hwid;
    `
	row := db.QueryRow(query, sql.Named("Hwid", hwid))
	var device models.Device
	err := row.Scan(&device.Id, &device.Hwid, &device.Uid, &device.LicenceKey, &device.DateTime)
	if err != nil {
		return nil, err
	}

	return &device, nil
}
