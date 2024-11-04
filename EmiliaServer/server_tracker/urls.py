from django.urls import path, include
from . import views

urlpatterns = [
    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),

    path('upload_torrent/', views.upload_torrent, name='upload_torrent'),
    path('manage_torrent/', views.manage_torrent, name='manage_torrent'),
    path('delete_torrent/<int:id>', views.delete_torrent, name='delete_torrent'),

    path('search_torrent/', views.search_torrent, name='search_torrent'),
    path('manage_user/', views.manage_user, name='manage_user'),
    path('delete_user/<int:id>', views.delete_user, name='delete_user'),
    path('edit_user/<int:id>', views.edit_user, name='edit_user'),

    path('view_statis/', views.view_stats, name='view_stats'),
    path('announce', views.announce, name='tracker_announce'),
    path('<str:info_hash>', views.torrent_details, name='torrent_detail'),  # New path for torrent list
    path('disconnect/<str:peer_id>/<int:torrent_id>/', views.disconnect_peer, name='disconnect_peer'),

    path('test/', views.test, name="test")
]
