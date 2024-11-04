from django import forms
from django.forms.widgets import DateInput
from django.contrib.auth.forms import UserCreationForm
from .models import *

class FormSettings(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super(FormSettings, self).__init__(*args, **kwargs)
        for field in self.visible_fields():
            field.field.widget.attrs['class'] = 'form-control'

class SignUpForm(UserCreationForm):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['password1'].label = 'Password'
        self.fields['password2'].label = 'Password Confirmation'

        self.fields['password1'].help_text = None
        self.fields['password2'].help_text = None
        for field in self.visible_fields():
            field.field.widget.attrs['class'] = 'form-control'

    class Meta:
        model = User
        fields = ('username', 'password1', 'password2' )
        help_texts = {
            'username': None,
        }

class TorrentFileUploadForm(forms.Form):
    torrent_file = forms.FileField()

class TorrentForm(forms.ModelForm):
    class Meta:
        model = Torrent
        fields = ['name', 'info_hash', 'announce', 'files', 'piece_length']
        widgets = {
            'files': forms.Textarea(attrs={'rows': 3}),
        }


class TorrentInfoForm(forms.ModelForm):
    class Meta:
        model = TorrentInfo
        fields = ['description']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 3}),
        }