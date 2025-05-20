unit SecureSQLHandler;

interface

uses
  System.SysUtils, System.Classes, System.Generics.Collections,
  Data.DB, FireDAC.Comp.Client, System.Hash, System.NetEncoding,
  System.StrUtils, System.Rtti;

type
  TParamDataType = (pdtString, pdtInteger, pdtFloat, pdtDate, pdtBoolean, pdtBlob);
  
  TSecureParameter = class
  private
    FName: string;
    FValue: Variant;
    FDataType: TParamDataType;
    FEncrypted: Boolean;
  public
    constructor Create(const AName: string; const AValue: Variant; ADataType: TParamDataType);
    function AsEncrypted: string;
    property Name: string read FName;
    property Value: Variant read FValue;
    property DataType: TParamDataType read FDataType;
    property Encrypted: Boolean read FEncrypted write FEncrypted;
  end;

  TSecureSQLQuery = class
  private
    FConnectionString: string;
    FOriginalSQL: string;
    FObfuscatedSQL: string;
    FParameters: TObjectList<TSecureParameter>;
    FConnection: TFDConnection;
    FQuery: TFDQuery;
    FSeed: string;
    FEncryptionKey: string;
    
    procedure SetSQL(const Value: string);
    function GetSQL: string;
    function ObfuscateSQL(const ASQL: string): string;
    function DeobfuscateSQL(const AObfuscatedSQL: string): string;
    function EncryptString(const AValue: string): string;
    function DecryptString(const AValue: string): string;
    procedure ApplyParametersToQuery;
  public
    constructor Create(const AConnectionString: string);
    destructor Destroy; override;
    
    procedure AddParameter(const AName: string; const AValue: Variant; ADataType: TParamDataType);
    function ParameterByName(const AName: string): TSecureParameter;
    
    function Execute: Integer;
    function Open: Boolean;
    
    property SQL: string read GetSQL write SetSQL;
    property Connection: TFDConnection read FConnection;
    property Query: TFDQuery read FQuery;
  end;

  TSecureSQLConnectionManager = class
  private
    FConnections: TDictionary<string, TFDConnection>;
    FEncryptedConnectionStrings: TDictionary<string, string>;
  public
    constructor Create;
    destructor Destroy; override;
    
    function AddConnection(const AName, AConnectionString: string): TFDConnection;
    function GetConnection(const AName: string): TFDConnection;
    procedure RemoveConnection(const AName: string);
    
    function EncryptConnectionString(const AConnectionString: string): string;
    function DecryptConnectionString(const AEncryptedString: string): string;
  end;

implementation

{ TSecureParameter }

constructor TSecureParameter.Create(const AName: string; const AValue: Variant; ADataType: TParamDataType);
begin
  FName := AName;
  FValue := AValue;
  FDataType := ADataType;
  FEncrypted := False;
end;

function TSecureParameter.AsEncrypted: string;
var
  Base64: TBase64Encoding;
begin
  Base64 := TBase64Encoding.Create;
  try
    case FDataType of
      pdtString:
        Result := Base64.Encode(VarToStr(FValue));
      pdtInteger:
        Result := Base64.Encode(IntToStr(FValue));
      pdtFloat:
        Result := Base64.Encode(FloatToStr(FValue));
      pdtDate:
        Result := Base64.Encode(DateTimeToStr(FValue));
      pdtBoolean:
        Result := Base64.Encode(BoolToStr(FValue, True));
      pdtBlob:
        Result := Base64.Encode('BLOB_DATA'); // Actual blob handling would be more complex
    end;
  finally
    Base64.Free;
  end;
  
  // Add some obfuscation with XOR against a rotating key
  Result := Result + '_' + THashSHA2.GetHashString(Result);
  FEncrypted := True;
end;

{ TSecureSQLQuery }

constructor TSecureSQLQuery.Create(const AConnectionString: string);
begin
  FConnectionString := AConnectionString;
  FParameters := TObjectList<TSecureParameter>.Create(True);
  
  // Generate a random seed and encryption key for this instance
  FSeed := THashSHA2.GetHashString(AConnectionString + TimeToStr(Now) + FloatToStr(Random));
  FEncryptionKey := THashSHA2.GetHashString(FSeed + IntToStr(Random(100000)));
  
  // Create connection and query components
  FConnection := TFDConnection.Create(nil);
  FConnection.ConnectionString := AConnectionString;
  
  FQuery := TFDQuery.Create(nil);
  FQuery.Connection := FConnection;
end;

destructor TSecureSQLQuery.Destroy;
begin
  FQuery.Free;
  FConnection.Free;
  FParameters.Free;
  inherited;
end;

procedure TSecureSQLQuery.AddParameter(const AName: string; const AValue: Variant; ADataType: TParamDataType);
var
  Param: TSecureParameter;
begin
  // Check if parameter already exists
  Param := ParameterByName(AName);
  if Param <> nil then
  begin
    FParameters.Remove(Param);
  end;
  
  // Add new parameter
  Param := TSecureParameter.Create(AName, AValue, ADataType);
  FParameters.Add(Param);
end;

function TSecureSQLQuery.ParameterByName(const AName: string): TSecureParameter;
var
  Param: TSecureParameter;
begin
  Result := nil;
  for Param in FParameters do
  begin
    if SameText(Param.Name, AName) then
    begin
      Result := Param;
      Break;
    end;
  end;
end;

function TSecureSQLQuery.GetSQL: string;
begin
  Result := FOriginalSQL;
end;

procedure TSecureSQLQuery.SetSQL(const Value: string);
begin
  FOriginalSQL := Value;
  FObfuscatedSQL := ObfuscateSQL(FOriginalSQL);
end;

function TSecureSQLQuery.EncryptString(const AValue: string): string;
var
  Base64: TBase64Encoding;
  XORKey: string;
  i: Integer;
  EncryptedChars: TArray<Char>;
begin
  // Create a XOR key from encryption key
  XORKey := FEncryptionKey;
  
  // XOR operation on the string
  SetLength(EncryptedChars, Length(AValue));
  for i := 1 to Length(AValue) do
  begin
    EncryptedChars[i-1] := Char(Ord(AValue[i]) xor Ord(XORKey[(i mod Length(XORKey)) + 1]));
  end;
  
  // Base64 encode the result
  Base64 := TBase64Encoding.Create;
  try
    Result := Base64.Encode(String(EncryptedChars));
  finally
    Base64.Free;
  end;
end;

function TSecureSQLQuery.DecryptString(const AValue: string): string;
var
  Base64: TBase64Encoding;
  XORKey: string;
  DecodedStr: string;
  i: Integer;
  DecryptedChars: TArray<Char>;
begin
  // Base64 decode
  Base64 := TBase64Encoding.Create;
  try
    DecodedStr := Base64.Decode(AValue);
  finally
    Base64.Free;
  end;
  
  // Create XOR key from encryption key
  XORKey := FEncryptionKey;
  
  // XOR operation to decrypt
  SetLength(DecryptedChars, Length(DecodedStr));
  for i := 1 to Length(DecodedStr) do
  begin
    DecryptedChars[i-1] := Char(Ord(DecodedStr[i]) xor Ord(XORKey[(i mod Length(XORKey)) + 1]));
  end;
  
  Result := String(DecryptedChars);
end;

function TSecureSQLQuery.ObfuscateSQL(const ASQL: string): string;
var
  Parts: TArray<string>;
  i: Integer;
  TokenizedSQL: string;
begin
  // Replace SQL keywords with tokens
  TokenizedSQL := ASQL;
  TokenizedSQL := ReplaceText(TokenizedSQL, 'SELECT', '##SEL##');
  TokenizedSQL := ReplaceText(TokenizedSQL, 'FROM', '##FRM##');
  TokenizedSQL := ReplaceText(TokenizedSQL, 'WHERE', '##WHR##');
  TokenizedSQL := ReplaceText(TokenizedSQL, 'JOIN', '##JIN##');
  TokenizedSQL := ReplaceText(TokenizedSQL, 'GROUP BY', '##GRP##');
  TokenizedSQL := ReplaceText(TokenizedSQL, 'ORDER BY', '##ORD##');
  TokenizedSQL := ReplaceText(TokenizedSQL, 'INSERT', '##INS##');
  TokenizedSQL := ReplaceText(TokenizedSQL, 'UPDATE', '##UPD##');
  TokenizedSQL := ReplaceText(TokenizedSQL, 'DELETE', '##DEL##');
  
  // Split by spaces and encrypt each part
  Parts := TokenizedSQL.Split([' ']);
  for i := 0 to High(Parts) do
  begin
    if Parts[i].StartsWith('##') and Parts[i].EndsWith('##') then
      Continue; // Don't encrypt tokens
    
    Parts[i] := EncryptString(Parts[i]);
  end;
  
  Result := String.Join(' ', Parts);
  
  // Add a hash signature to verify integrity
  Result := Result + '|' + THashSHA2.GetHashString(Result + FEncryptionKey);
end;

function TSecureSQLQuery.DeobfuscateSQL(const AObfuscatedSQL: string): string;
var
  SQL, Hash: string;
  Parts: TArray<string>;
  PipePosn: Integer;
  i: Integer;
  DeobfuscatedParts: TArray<string>;
begin
  // Extract SQL and hash
  PipePosn := AObfuscatedSQL.LastIndexOf('|');
  if PipePosn <= 0 then
    raise Exception.Create('Invalid obfuscated SQL format');
    
  SQL := AObfuscatedSQL.Substring(0, PipePosn);
  Hash := AObfuscatedSQL.Substring(PipePosn + 1);
  
  // Verify hash
  if Hash <> THashSHA2.GetHashString(SQL + FEncryptionKey) then
    raise Exception.Create('SQL integrity verification failed');
  
  // Split and decrypt parts
  Parts := SQL.Split([' ']);
  SetLength(DeobfuscatedParts, Length(Parts));
  
  for i := 0 to High(Parts) do
  begin
    if Parts[i].StartsWith('##') and Parts[i].EndsWith('##') then
    begin
      // Restore SQL keywords
      if Parts[i] = '##SEL##' then DeobfuscatedParts[i] := 'SELECT'
      else if Parts[i] = '##FRM##' then DeobfuscatedParts[i] := 'FROM'
      else if Parts[i] = '##WHR##' then DeobfuscatedParts[i] := 'WHERE'
      else if Parts[i] = '##JIN##' then DeobfuscatedParts[i] := 'JOIN'
      else if Parts[i] = '##GRP##' then DeobfuscatedParts[i] := 'GROUP BY'
      else if Parts[i] = '##ORD##' then DeobfuscatedParts[i] := 'ORDER BY'
      else if Parts[i] = '##INS##' then DeobfuscatedParts[i] := 'INSERT'
      else if Parts[i] = '##UPD##' then DeobfuscatedParts[i] := 'UPDATE'
      else if Parts[i] = '##DEL##' then DeobfuscatedParts[i] := 'DELETE'
      else DeobfuscatedParts[i] := Parts[i];
    end
    else
    begin
      DeobfuscatedParts[i] := DecryptString(Parts[i]);
    end;
  end;
  
  Result := String.Join(' ', DeobfuscatedParts);
end;

procedure TSecureSQLQuery.ApplyParametersToQuery;
var
  Param: TSecureParameter;
  QueryParam: TFDParam;
begin
  // Clear existing parameters
  FQuery.Params.Clear;
  
  // Apply each parameter to the query
  for Param in FParameters do
  begin
    QueryParam := FQuery.Params.Add;
    QueryParam.Name := Param.Name;
    
    case Param.DataType of
      pdtString:
        QueryParam.AsString := Param.Value;
      pdtInteger:
        QueryParam.AsInteger := Param.Value;
      pdtFloat:
        QueryParam.AsFloat := Param.Value;
      pdtDate:
        QueryParam.AsDateTime := Param.Value;
      pdtBoolean:
        QueryParam.AsBoolean := Param.Value;
      pdtBlob:
        begin
          QueryParam.DataType := ftBlob;
          // Here you would handle blob data appropriately
        end;
    end;
  end;
end;

function TSecureSQLQuery.Execute: Integer;
begin
  try
    // Prepare the connection
    if not FConnection.Connected then
      FConnection.Open;
      
    // Set the query SQL (deobfuscated)
    FQuery.SQL.Text := DeobfuscateSQL(FObfuscatedSQL);
    
    // Apply parameters
    ApplyParametersToQuery;
    
    // Execute query
    FQuery.ExecSQL;
    Result := FQuery.RowsAffected;
  except
    on E: Exception do
    begin
      // Log the error but don't expose the actual SQL
      raise Exception.Create('Error executing secure SQL query: ' + E.Message);
    end;
  end;
end;

function TSecureSQLQuery.Open: Boolean;
begin
  try
    // Prepare the connection
    if not FConnection.Connected then
      FConnection.Open;
      
    // Set the query SQL (deobfuscated)
    FQuery.SQL.Text := DeobfuscateSQL(FObfuscatedSQL);
    
    // Apply parameters
    ApplyParametersToQuery;
    
    // Open query
    FQuery.Open;
    Result := not FQuery.IsEmpty;
  except
    on E: Exception do
    begin
      // Log the error but don't expose the actual SQL
      raise Exception.Create('Error opening secure SQL query: ' + E.Message);
      Result := False;
    end;
  end;
end;

{ TSecureSQLConnectionManager }

constructor TSecureSQLConnectionManager.Create;
begin
  FConnections := TDictionary<string, TFDConnection>.Create;
  FEncryptedConnectionStrings := TDictionary<string, string>.Create;
end;

destructor TSecureSQLConnectionManager.Destroy;
var
  Connection: TFDConnection;
begin
  for Connection in FConnections.Values do
  begin
    Connection.Free;
  end;
  
  FConnections.Free;
  FEncryptedConnectionStrings.Free;
  inherited;
end;

function TSecureSQLConnectionManager.AddConnection(const AName, AConnectionString: string): TFDConnection;
var
  Connection: TFDConnection;
  EncryptedString: string;
begin
  // Encrypt the connection string
  EncryptedString := EncryptConnectionString(AConnectionString);
  
  // Create and store the connection
  Connection := TFDConnection.Create(nil);
  Connection.ConnectionString := AConnectionString;
  
  FConnections.Add(AName, Connection);
  FEncryptedConnectionStrings.Add(AName, EncryptedString);
  
  Result := Connection;
end;

function TSecureSQLConnectionManager.GetConnection(const AName: string): TFDConnection;
begin
  if not FConnections.TryGetValue(AName, Result) then
    Result := nil;
end;

procedure TSecureSQLConnectionManager.RemoveConnection(const AName: string);
var
  Connection: TFDConnection;
begin
  if FConnections.TryGetValue(AName, Connection) then
  begin
    Connection.Free;
    FConnections.Remove(AName);
    FEncryptedConnectionStrings.Remove(AName);
  end;
end;

function TSecureSQLConnectionManager.EncryptConnectionString(const AConnectionString: string): string;
var
  Base64: TBase64Encoding;
  Key: string;
  i: Integer;
  EncryptedChars: TArray<Char>;
begin
  // Create a simple encryption key
  Key := THashSHA2.GetHashString('SecureSQL' + FormatDateTime('yyyymmdd', Date));
  
  // XOR operation on each character
  SetLength(EncryptedChars, Length(AConnectionString));
  for i := 1 to Length(AConnectionString) do
  begin
    EncryptedChars[i-1] := Char(Ord(AConnectionString[i]) xor Ord(Key[(i mod Length(Key)) + 1]));
  end;
  
  // Base64 encode the result
  Base64 := TBase64Encoding.Create;
  try
    Result := Base64.Encode(String(EncryptedChars));
  finally
    Base64.Free;
  end;
end;

function TSecureSQLConnectionManager.DecryptConnectionString(const AEncryptedString: string): string;
var
  Base64: TBase64Encoding;
  Key: string;
  DecodedStr: string;
  i: Integer;
  DecryptedChars: TArray<Char>;
begin
  // Create the same encryption key
  Key := THashSHA2.GetHashString('SecureSQL' + FormatDateTime('yyyymmdd', Date));
  
  // Base64 decode
  Base64 := TBase64Encoding.Create;
  try
    DecodedStr := Base64.Decode(AEncryptedString);
  finally
    Base64.Free;
  end;
  
  // XOR operation to decrypt
  SetLength(DecryptedChars, Length(DecodedStr));
  for i := 1 to Length(DecodedStr) do
  begin
    DecryptedChars[i-1] := Char(Ord(DecodedStr[i]) xor Ord(Key[(i mod Length(Key)) + 1]));
  end;
  
  Result := String(DecryptedChars);
end;

end.