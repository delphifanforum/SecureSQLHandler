# SecureSQLHandler

A secure SQL query handling library for Delphi applications that provides obfuscation and protection for SQL statements and parameters.

## Overview

SecureSQLHandler is designed to enhance security in Delphi applications that work with databases by preventing SQL injection and protecting sensitive query information. The library obfuscates SQL queries and parameters, making it difficult for malicious actors to intercept or understand database interactions.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Delphi Compatibility](https://img.shields.io/badge/delphi-10.3+-orange.svg)

## Features

- **SQL Query Obfuscation**: Automatically transforms SQL statements into an encrypted format
- **Parameter Security**: Encrypts and secures query parameters
- **Connection String Protection**: Securely stores and manages database connection strings
- **SQL Integrity Verification**: Ensures SQL hasn't been tampered with via hash signatures
- **FireDAC Integration**: Seamlessly works with Delphi's FireDAC components
- **Minimal Performance Impact**: Designed for efficiency with negligible overhead

## Requirements

- Delphi 10.3 or higher
- FireDAC components (included with Delphi)

## Installation

1. Clone the repository or download the source code
2. Add the `SecureSQLHandler.pas` file to your project
3. Add the unit to your uses clause

```pascal
uses
  SecureSQLHandler;
```

## Quick Start Guide

### Basic Usage

```pascal
// Create a secure SQL query
var
  SecureQuery: TSecureSQLQuery;
  ConnectionString: string;
begin
  // Set up connection string
  ConnectionString := 'DriverID=MSSQL;Server=myserver;Database=mydb;User_Name=user;Password=pwd;';
  
  // Create the query object
  SecureQuery := TSecureSQLQuery.Create(ConnectionString);
  try
    // Set SQL (will be automatically obfuscated)
    SecureQuery.SQL := 'SELECT * FROM Customers WHERE CustomerID = :ID';
    
    // Add parameters
    SecureQuery.AddParameter('ID', 1234, pdtInteger);
    
    // Execute query
    if SecureQuery.Open then
    begin
      // Process results
      while not SecureQuery.Query.Eof do
      begin
        // Access fields via SecureQuery.Query.FieldByName
        ShowMessage(SecureQuery.Query.FieldByName('CustomerName').AsString);
        SecureQuery.Query.Next;
      end;
    end;
  finally
    SecureQuery.Free;
  end;
end;
```

### Using the Connection Manager

```pascal
var
  ConnectionManager: TSecureSQLConnectionManager;
  Connection: TFDConnection;
begin
  ConnectionManager := TSecureSQLConnectionManager.Create;
  try
    // Add and encrypt a connection
    ConnectionManager.AddConnection('MainDB', 
      'DriverID=MSSQL;Server=myserver;Database=mydb;User_Name=user;Password=pwd;');
    
    // Get the connection when needed
    Connection := ConnectionManager.GetConnection('MainDB');
    
    // Use the connection with standard FireDAC components if needed
    // ...
    
  finally
    ConnectionManager.Free;
  end;
end;
```

## Detailed Examples

See the included `SecureSQLDemo.pas` for a comprehensive example of using the library.

## Security Features

### SQL Obfuscation Process

1. SQL keywords (SELECT, FROM, WHERE, etc.) are tokenized
2. Remaining SQL parts are encrypted with a session-specific key
3. A hash signature is appended to verify integrity
4. The entire SQL statement is transformed into an unreadable format

### Parameter Security

Parameters are encrypted before being stored and are only decrypted when needed for query execution. This prevents sensitive parameter values from being exposed in memory dumps or through debugging tools.

### Connection String Protection

Connection strings contain sensitive information such as server addresses, usernames, and passwords. The library encrypts these strings and only decrypts them when establishing connections.

## Performance Considerations

The library is designed to have minimal impact on performance:
- Encryption is optimized for speed
- SQL statements are only obfuscated once, then cached
- Connection overhead is negligible

## Best Practices

For maximum security:

1. Never expose the obfuscated SQL or encrypted parameters in logs or debug output
2. Store the library's encryption keys securely
3. Use parameterized queries for ALL user input
4. Regularly rotate encryption keys for production environments

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by the need for better SQL security in Delphi applications
- Thanks to all contributors and users for their feedback and support
