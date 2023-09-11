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

from wso2_app.serializers import UploadedFileSerializer
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

@api_view(['POST'])
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

        response = requests.post(url=url, headers=headers, json=data, verify=False)  # Use verify=False to ignore SSL 
        return Response(status=response.status_code,data=response.json())
    except Exception:
            return Response(data={"detail":"raised an Exception"}, status=status.HTTP_404_NOT_FOUND)  
        
@api_view(['POST'])
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
            "username": f'{username}',
            "password": f'{password}',
            "scope": "apim:api_view apim:api_create",
        }
        response = requests.post(url=url, headers=headers, data=data, verify=False)  # Use verify=False to ignore SSL

        return Response(status=response.status_code,data=response.json())
    except Exception:
             return Response(data={"detail":"raised an Exception"}, status=status.HTTP_404_NOT_FOUND)  

@api_view(['GET'])
@permission_classes((AllowAny,))
def get_apis(request):
    try:
       # curl -k -H "Authorization: Bearer ae4eae22-3f65-387b-a171-d37eaa366fa8" "https://127.0.0.1:9443/api/am/publisher/v2/apis"

        authorization_header = request.META.get("HTTP_AUTHORIZATION")
        print(authorization_header,"ADAD")
        if authorization_header:
            # Extract the bearer token (assuming "Bearer" prefix)
            header_splited = authorization_header.split()
            if header_splited[0]== "Bearer":
                bearer_token = header_splited[1]                
        url = "https://172.28.5.32:9443/api/am/publisher/v2/apis"
        
        print(bearer_token)
        headers = {
                   'Authorization': f'Bearer {bearer_token}',
                  }
        print(headers)
   
        response = requests.get(url=url, headers=headers,verify=False)  # Use verify=False to ignore SSL 
        try:
            return Response(status=response.status_code,data=response.json())
        except Exception:
            return Response(status=response.status_code,data=response.content)
    except Exception:
             return Response(data={"detail":"raised an Exception"}, status=status.HTTP_404_NOT_FOUND)      
         
@api_view(['POST'])
@permission_classes((AllowAny,))
def creatre_api(request):
    try:
        name=request.data.get("name")
        description=request.data.get("description")
        context=request.data.get("context")
        version=request.data.get("version")
        provider=request.data.get("provider")
        lifeCycleStatus=request.data.get("lifeCycleStatus")
        
        data = {
            "name": f'{name}',
            "description": f'{description}',
            "context": f'{context}',
            "version": f'{version}',
            "provider": f'{provider}',
            "lifeCycleStatus": f'{lifeCycleStatus}',
        }
       # curl -k -H "Authorization: Bearer ae4eae22-3f65-387b-a171-d37eaa366fa8" "https://127.0.0.1:9443/api/am/publisher/v2/apis"

        authorization_header = request.META.get("HTTP_AUTHORIZATION")
        if authorization_header:
            header_splited = authorization_header.split()
            if header_splited[0]== "Bearer":
                bearer_token = header_splited[1]                
        url = "https://172.28.5.32:9443/api/am/publisher/v2/apis"
        
        headers = {
                   'Authorization': f'Bearer {bearer_token}',
                    'Content-Type': 'application/json'                   
                  }
        response = requests.post(url=url, headers=headers, json=data, verify=False)  # Use verify=False to ignore SSL 
        try:
            return Response(status=response.status_code,data=response.json())
        except Exception:
            return Response(status=response.status_code,data=response.content)
    except Exception:
             return Response(data={"detail":"raised an Exception"}, status=status.HTTP_404_NOT_FOUND)              
    
    
class API_RUD(APIView):

    def get(self,request,apiId):
        try:     
     # curl -k -H "Authorization: Bearer ae4eae22-3f65-387b-a171-d37eaa366fa8" "https://127.0.0.1:9443/api/am/publisher/v2/apis/7a2298c4-c905-403f-8fac-38c73301631f" 
            authorization_header = request.META.get("HTTP_AUTHORIZATION")
            if authorization_header:
                header_splited = authorization_header.split()
                if header_splited[0]== "Bearer":
                    bearer_token = header_splited[1]                
                    url = f"https://172.28.5.32:9443/api/am/publisher/v2/apis/{apiId}"

                    headers = {
                               'Authorization': f'Bearer {bearer_token}',
                              }
            response = requests.get(url=url, headers=headers, verify=False)  # Use verify=False to ignore SSL 
            try:
                return Response(status=response.status_code,data=response.json())
            except Exception:
                return Response(status=response.status_code,data=response.content)
        except Exception:
                 return Response(data={"detail":"raised an Exception"}, status=status.HTTP_404_NOT_FOUND) 
    def put(self,request,apiId):
        #try:     
            name=request.data.get("name")
            context=request.data.get("context")
            version=request.data.get("version")
            description=request.data.get("description")
            

            data = {
                "name": f'{name}',
                "context": f'{context}',
                "version": f'{version}',
                "description": f"{description}"
            }
     # curl -k -X PUT -H "Authorization: Bearer ae4eae22-3f65-387b-a171-d37eaa366fa8" -H "Content-Type: application/json" -d @data.json "https://127.0.0.1:9443/api/am/publisher/v2/apis/7a2298c4-c905-403f-8fac-38c73301631f"

            authorization_header = request.META.get("HTTP_AUTHORIZATION")
            if authorization_header:
                header_splited = authorization_header.split()
                if header_splited[0]== "Bearer":
                    bearer_token = header_splited[1]                
                    url = f"https://172.28.5.32:9443/api/am/publisher/v2/apis/{apiId}"

                    headers = {
                               'Authorization': f'Bearer {bearer_token}',
                               'Content-Type': 'application/json'
                              }
            response = requests.put(url=url, headers=headers,json=data, verify=False)  # Use verify=False to ignore SSL 
            try:
                return Response(status=response.status_code,data=response.json())
            except Exception:
                return Response(status=response.status_code,data=response.content)
        #except Exception:
        #         return Response(data={"detail":"raised an Exception"}, status=status.HTTP_404_NOT_FOUND)     

    def delete(self,request,apiId):
        #curl -k -X DELETE -H "Authorization: Bearer ae4eae22-3f65-387b-a171-d37eaa366fa8" "https://127.0.0.1:9443/api/am/publisher/v2/apis/7a2298c4-c905-403f-8fac-38c73301631f"
        try:     
            authorization_header = request.META.get("HTTP_AUTHORIZATION")
            if authorization_header:
                header_splited = authorization_header.split()
                if header_splited[0]== "Bearer":
                    bearer_token = header_splited[1]                
                    url = f"https://172.28.5.32:9443/api/am/publisher/v2/apis/{apiId}"

                    headers = {
                               'Authorization': f'Bearer {bearer_token}',
                              }
            response = requests.delete(url=url, headers=headers, verify=False)  # Use verify=False to ignore SSL 
            try:
                return Response(status=response.status_code,data=response.json())
            except Exception:
                return Response(status=response.status_code,data=response.content)
        except Exception:
                 return Response(data={"detail":"raised an Exception"}, status=status.HTTP_404_NOT_FOUND)   
import datetime
from .models import UploadedFile
class ApiSwagger(APIView):
    from rest_framework.parsers import MultiPartParser, FormParser,FileUploadParser    
  #  parser_classes = (MultiPartParser,)
    def get(self,request,apiId):
        try:     
# curl -k -H "Authorization: Bearer ae4eae22-3f65-387b-a171-d37eaa366fa8" "https://127.0.0.1:9443/api/am/publisher/v2/apis/7a2298c4-c905-403f-8fac-38c73301631f/swagger"            
#curl -k -X PUT -H "Authorization: Bearer ae4eae22-3f65-387b-a171-d37eaa366fa8" -F apiDefinition=@swagger.json "https://127.0.0.1:9443/api/am/publisher/v2/apis/96077508-fd01-4fae-bc64-5de0e2baf43c/swagger"            authorization_header = request.META.get("HTTP_AUTHORIZATION")
            authorization_header = request.META.get("HTTP_AUTHORIZATION")
            
            if authorization_header:
                header_splited = authorization_header.split()
                if header_splited[0]== "Bearer":

                    bearer_token = header_splited[1]                
                    url = f"https://172.28.5.32:9443/api/am/publisher/v2/apis/{apiId}/swagger"

                    headers = {
                               'Authorization': f'Bearer {bearer_token}',
                              }
            response = requests.get(url=url, headers=headers, verify=False)  # Use verify=False to ignore SSL 
            try:
                return Response(status=response.status_code,data=response.json())
            except Exception:
                return Response(status=response.status_code,data=response.content)
        except Exception:
                 return Response(data={"detail":"raised an Exception"}, status=status.HTTP_404_NOT_FOUND) 
             

   
    def put(self,request,apiId):
        try:     
     # curl -k -X PUT -H "Authorization: Bearer ae4eae22-3f65-387b-a171-d37eaa366fa8" -H "Content-Type: application/json" -d @data.json "https://127.0.0.1:9443/api/am/publisher/v2/apis/7a2298c4-c905-403f-8fac-38c73301631f"
            # data = {
            # "file": request.POST.get('title', None),
            # }
            authorization_header = request.META.get("HTTP_AUTHORIZATION")
            uploaded_file = request.FILES.get('apiDefinition')
            print(type(uploaded_file), "CACACACACCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCc")
            print(uploaded_file, "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
            if authorization_header:
                
                header_splited = authorization_header.split()
                if header_splited[0]== "Bearer":
                    
                    bearer_token = header_splited[1]                
                    url = f"https://172.28.5.32:9443/api/am/publisher/v2/apis/{apiId}/swagger"


                    headers = {
                               'Authorization': f'Bearer {bearer_token}',
                              }
          
            #file_serializer = UploadedFileSerializer(data=request.data.get("apiDefinition"))
            #if file_serializer.is_valid():
            #    print("dawdqawd")
            #    
            #    file_serializer.save()   
            #recent_file = UploadedFile.objects.latest('-id')
            #path = recent_file.file.path      
            file=UploadedFile.objects.create(file=uploaded_file)
            file.save()
            recent_file = UploadedFile.objects.latest('-id')
            files = {
                    'apiDefinition': open(recent_file.file.path, 'rb')
                    }  
                               
            response = requests.put(url=url, headers=headers, files=files, verify=False)  # Use verify=False to ignore SSL 
            try:
                return Response(status=response.status_code,data=response.json())
            except Exception:
                return Response(status=response.status_code,data=response.content)
        except Exception:
                 return Response(data={"detail":"raised an Exception"}, status=status.HTTP_404_NOT_FOUND)     
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