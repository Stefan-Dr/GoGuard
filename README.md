# GoGuard 🛡️

GoGuard is a secure API service written in Go for managing license issuance tied to hardware identifiers (HWID). 

The system is designed with security in mind, utilizing RSA for key exchange and signatures, and AES-256-GCM for encrypted communication.

The server supports handling license requests for multiple devices simultaneously.  
Clients can request licenses for multiple hardware IDs (HWIDs) within separate sessions or in sequence.  
The server validates each HWID independently and returns the corresponding encrypted license if available.


---

## ✨ Features

- Secure RSA-based handshake and session management  
- Digital signature verification with mutual trust confirmation per session
- Secure AES-256 key delivery per session  
- License issuing per unique HWID  
- Session expiration and cleanup to prevent misuse  
- Simple and clear API structure with meaningful responses  

---

## 🚩 API Overview

| Method | Path               | Purpose                            |
|--------|--------------------|----------------------------------|
| GET    | `/ping`            | Health check                     |
| POST   | `/handshake`       | Initialize session and exchange RSA keys |
| POST   | `/digital-signature` | Verify or create digital signature |
| GET    | `/get-key`         | Retrieve AES encryption key      |
| POST   | `/licence`         | Validate HWID and receive license |

---

## 📖 Full API Documentation:  
👉 [GoGuard Wiki - API & Database Documentation](https://github.com/Stefan-Dr/GoGuard/wiki/GoGuard)

---

## 🛠️ Technologies Used

- Go (Golang)  
- Gin HTTP Framework  
- `golang.org/x/time/rate` for rate limiting middleware
- RSA / AES-256-GCM Cryptography  
- SQL Server for device and license storage  

---

## 📥 Installing Go

Download and install **Go** from the official website: [https://go.dev/dl/](https://go.dev/dl/)

After installation, verify it by running:

```bash
go version
```

---

## 📂 Project Structure
```
GoGuard/  
├── crypto/               # RSA / AES encryption utilities  
│   ├── aes.go  
│   ├── aes_test.go  
│   ├── licence.go  
│   ├── licence_test.go  
│   ├── rsa.go  
│   └── rsa_test.go  
│  
├── db/                   # Database queries  
│   └── db.go  
│  
├── models/               # Data models  
│   └── types.go  
│  
├── server/               # Server logic and API route handlers  
│   ├── aes_key.go  
│   ├── config.go  
│   ├── digital_signature.go  
│   ├── handshake.go  
│   ├── licence.go
│   ├── rate_limiter.go  
│   └── server.go  
│ 
├── config.json           # API and Database configurations  
├── main.go               # Application entrypoint  
└── README.md             # Project documentation  
```

---

## ⚙️ Running the Project

Before running the project, ensure that your SQL Server database is properly configured and that the specified table exists.

Refer to the [**Database Schema**](https://github.com/Stefan-Dr/GoGuard/wiki/GoGuard#database-schema) for expected schema details.

You must also provide a valid `config.json` file at the project root

>🔔 **Note:** 
> If you run the `init-database.sql` script in **SQL Server Management Studio** and create the database that way,
> it is enough to simply configure your `config.json` with your own **server name**, **username**, and **password**.  
> 
> Make sure to use **SQL Server Authentication** (not Windows Authentication).

Open `Terminal` and position yourselft in the **GoGuard** directory, then run

```bash
go run main.go
```

## 🧪 Running Tests

To run all unit tests in the project, run the following command in the project root directory:

```bash
go test ./... -v
```

This will recursively execute all tests in the project.

## 📌 Example Use Case

A client program wants to verify if the device it is running on is valid and authorized. The flow is as follows:

1. The client initiates a secure handshake with the server to exchange RSA keys.
2. It performs digital signature verification to mutually confirm the identities.
3. The client then requests the AES key, which the server provides encrypted with the client’s RSA public key.
4. Using the AES key, the client sends its hardware ID (HWID) encrypted and requests a license.
5. The server returns the license encrypted with AES if a valid license exists for that HWID.

This process ensures the client device is authenticated and authorized to use the service securely.

## 👨‍💻 Author

  
- [**Stefan Drljevic**](https://github.com/Stefan-Dr)