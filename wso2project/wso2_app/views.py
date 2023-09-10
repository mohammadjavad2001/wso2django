import logging
from rest_framework_simplejwt.tokens import RefreshToken
from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework import status, permissions
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.authentication import SessionAuthentication
from hashlib import sha256
from django.http import JsonResponse
import time
from rest_framework_simplejwt.tokens import RefreshToken
from .models import *
from django.core.cache import cache
from rest_framework.decorators import api_view, permission_classes, authentication_classes
import uuid
import json
import random
from django.utils import timezone
from django.conf import settings
import base64
import requests
import subprocess
@api_view(['GET','POST'])
@permission_classes((AllowAny,))
def register(request):
    try:
        username=request.data.get("admin_username")
        password=request.data.get("admin_password")
        input_string=f'{username}:{password}'
        encoded_bytes = base64.b64encode(input_string.encode("utf-8"))

        # Convert the bytes to a base64 string
        encoded_utf8 = encoded_bytes.decode("utf-8")
        print(encoded_utf8)
        
        #product_id = request.query_params.get('id')

        url = "https://172.28.5.32:9443/client-registration/v0.17/register"
        headers = {
                    'Authorization': f'Basic {encoded_utf8}',
                    'Content-Type': 'application/json'
                    }
        print(headers)
        
        data={   "callbackUrl":"http://192.168.107.23:8000/wso2/register/",
                 "clientName":"rest_api_publisher",
                 "owner":"admin",
                 "grantType":"client_credentials password refresh_token",
                 "saasApp":"true"
                 }

        response = requests.post(url=url, headers=headers, json=data, verify=False)  # Use verify=False to ignore SSL certificate validation (for testing only)
        return Response(status=response.status_code,data=response.json())
    except Exception:
            return Response(data={"detail":"NOT FOUND"}, status=status.HTTP_404_NOT_FOUND)  
        
@api_view(['GET','POST'])
@permission_classes((AllowAny,))
def get_token(request):
    try:
        clientId=request.data.get("clientId")
        clientSecret=request.data.get("clientSecret")
        username=request.data.get("admin_username")
        password=request.data.get("admin_password")
                
        input_string=f'{clientId}:{clientSecret}'

        encoded_bytes = base64.b64encode(input_string.encode("utf-8"))

        # Convert the bytes to a base64 string
        encoded_utf8 = encoded_bytes.decode("utf-8")
        print(encoded_utf8)
    
        url = "https://172.28.5.32:9443/oauth2/token"
        headers = {
                    'Authorization': f'Basic {encoded_utf8}',
                    'Content-Type': "application/x-www-form-urlencoded",
                    }
        print(headers)
        #data1 = "grant_type=password&username=admin&password=123&scope=apim:api_view apim:api_create"
        #print(f"{data1}")
        data = {
            "grant_type": "password",
            "username": "admin",
            "password": "123",
            "scope": "apim:api_view apim:api_create",
        }
        response = requests.post(url=url, headers=headers, data=data, verify=False)  # Use verify=False to ignore SSL certificate validation (for testing only)

        return Response(status=response.status_code,data=response.json())
    except Exception:
             return Response(data={"detail":"NOT FOUND"}, status=status.HTTP_404_NOT_FOUND)  
    
    
# import http.client
# import json        
# import http.client
# import json

# # Define the request headers
# headers = {
#     "Authorization": "Basic Zk9DaTR2Tko1OVBwSHVjQzJDQVlmWXVBRGRNYTphNEZ3SGxxMGlDSUtWczJNUElJRG5lcFpuWU1h",
#     "Content-Type": "application/x-www-form-urlencoded",
# }

# # Define the payload data as a string
# data = "grant_type=password&username=admin&password=admin&scope=apim:api_view apim:api_create"

# # Define the URL
# url = "/oauth2/token"

# # Establish a connection to the server
# connection = http.client.HTTPSConnection("localhost", 9443)  # Adjust the host and port as needed

# # Send the POST request
# connection.request("POST", url, body=data, headers=headers)

# # Get the response
# response = connection.getresponse()

# # Print the response status code
# print(response.status)

# # Read and print the response data
# response_data = response.read()
# print(response_data.decode('utf-8'))        