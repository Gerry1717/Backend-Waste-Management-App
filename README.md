# WasteManagementMobileApp/BackEnd
Node.js backend Server with MongoDB storage intergrated by a mongoose driver  

# Testing the APIs
With Curl on windows cmd: 

## Register User (Username:gerry, Password:hashedpassword)
curl -X POST -H "Content-Type: application/json" -d "{\"name\":\"Micky Mouse\", \"username\":\"micky\", \"password\":\"hashedpassword\"}" http://192.168.1.7:8080/api/register
 #### Expected Result: {"message":"User registered successfully","username":"<USERNAME>"}
 #### Error: {"error":"User already exists"}

## Test Login (Assuming User is Already Registered)
curl -X POST -H "Content-Type: application/json" -d "{\"username\": \"aUser\", \"password\": \"hashedpassword\"}" --insecure https://localhost:8080/api/login
#### Expected Return: {"message":"Login successful SessionID: ","sessionID":"<SESSION_ID>"}

## Test Logout
>curl -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <Token from login>" -d "{\"username\": \"milo\", \"password\": \"hashedpassword\"}" --insecure https://localhost/logout
 #### Expected Return: {"message":"Logout successful"}

## Test to List array of all items in a user’s Fridge
curl -k -H "Authorization: Bearer <Token>" https://localhost:443/user-fridge-items

## Test Adding new item to Fridge via Barcode from products DataBase
curl -k -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <Auth Token>" -d "{\"barcode\":\"345678901234\"}" https://localhost/user-add-to-fridge

## Test Updating Expiry date of existing Item
curl -k -X POST -H "Content-Type: application/json" -H "Authorization: Bearer <Auth Token>" -d "{\"barcode\": \"123456789012\", \"newExpiry\": \"2023-12-31\"}" https://localhost/update-expiry

## Test Removing Item from Fridge
curl -k -X DELETE -H "Content-Type: application/json" -H "Authorization: Bearer <Token>-" -d "{\"barcode\": \"123456789012\"}" https://localhost/user-remove-from-fridge
Expected Result: {"message":"Item removed from the fridge successfully"}

## Test Clearing all Items from User Fridge 
curl -k -X DELETE -H "Content-Type: application/json" -H "Authorization: Bearer <Token>" https://localhost/user-clear-fridge
#### Expected Result: {"message":"Fridge cleared successfully"}

## Adds new item to Catalogue
curl -X POST "http://192.168.1.7:8080/api/add-to-catalogue" -H "Content-Type: application/json" -H "Authorization: Bearer <Token>" -d "{\"barcode\":\"656667686972\",\"name\": \"Test Product\"}"

