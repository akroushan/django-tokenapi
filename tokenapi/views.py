from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
from app.util import *
import urllib2 
import json

try:
    from django.contrib.auth import get_user_model
except ImportError: # Django < 1.5
    from django.contrib.auth.models import User
else:
    User = get_user_model()

from tokenapi.tokens import token_generator
from tokenapi.http import JsonResponse, JsonError, JsonResponseForbidden, JsonResponseUnauthorized


# Creates a token if the correct username and password is given
# token/new.json
# Required: username&password
# Returns: success&token&user
@csrf_exempt
def token_new(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        mode = request.POST.get('mode')
        access_token = request.POST.get('access_token')
        
    	if mode and access_token:
    		if mode == 'facebook':
    			response =  urllib2.urlopen("https://graph.facebook.com/v2.1/me?access_token="+access_token+"&format=json&method=get&pretty=0&suppress_http_code=1")
    			output = response.read()
                output = json.loads(output)
                try:
                    email = output['email']
                except KeyError:
                    return JsonError("Access token not valid")
                first_name = output['first_name']
                last_name = output['last_name']
                gender = output['gender']
                dob = None
                mobile = None
                password = None
                mode = "facebook"
                try:
                    user = User.objects.get(username=email)
                except User.DoesNotExist:
                    a = create_new_user(email, password, first_name, last_name, dob, gender, mobile, mode)
                    print a
                    user = User.objects.get(username=email)
                data = {
                        'token': token_generator.make_token(user),
                        'user': user.pk,
                }

                return JsonResponse(data)

        elif username and password:
            user = authenticate(username=username, password=password, mode=mode, access_token= access_token)

            if user:
                TOKEN_CHECK_ACTIVE_USER = getattr(settings, "TOKEN_CHECK_ACTIVE_USER", False)

                if TOKEN_CHECK_ACTIVE_USER and not user.is_active:
                    return JsonResponseForbidden("User account is disabled.")

                data = {
                    'token': token_generator.make_token(user),
                    'user': user.pk,
                }
                return JsonResponse(data)
            else:
                return JsonResponseUnauthorized("Unable to log you in, please try again.")
        else:
            return JsonError("Must include 'username' and 'password' or 'username' and 'mode' and 'access_token' as POST parameters.")
    else:
        return JsonError("Must access via a POST request.")

# Checks if a given token and user pair is valid
# token/:token/:user.json
# Required: user
# Returns: success
def token(request, token, user):
    try:
        user = User.objects.get(pk=user)
    except User.DoesNotExist:
        return JsonError("User does not exist.")

    TOKEN_CHECK_ACTIVE_USER = getattr(settings, "TOKEN_CHECK_ACTIVE_USER", False)

    if TOKEN_CHECK_ACTIVE_USER and not user.is_active:
        return JsonError("User account is disabled.")

    if token_generator.check_token(user, token):
        return JsonResponse({})
    else:
        return JsonError("Token did not match user.")
