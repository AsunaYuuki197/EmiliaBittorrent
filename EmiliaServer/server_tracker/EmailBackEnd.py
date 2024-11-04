from django.contrib.auth.backends import ModelBackend
from django.contrib.auth import get_user_model

# custom auth function for login via email + password
class EmailBackEnd(ModelBackend):
    def authenticate(self, username = None, password = None, **kwargs):
        # create and get user model
        UserModel = get_user_model()
        # try fetch data from db
        try:
            user = UserModel.objects.get(email=username)
        # handle usermodel not exist
        except UserModel.DoesNotExist:
            return None
        else:
            if user.check_password(password):
                return user
        return None
