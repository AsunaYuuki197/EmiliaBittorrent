from django.db import models
from django.contrib.auth.models import User

class Torrent(models.Model):
    # The basic fields for the torrent
    torrent_file = models.FileField(upload_to="torrents/", null=True, blank=True, max_length=400)  
    torrent_url = models.URLField(null=True, blank=True, max_length=400)  # Firebase download URL

    name = models.TextField()
    info_hash = models.CharField(max_length=40, unique=True) 
    announce = models.TextField() 
    creation_date = models.BigIntegerField(null=True, blank=True)  
    comment = models.TextField(null=True, blank=True)  
    created_by = models.CharField(max_length=255, null=True, blank=True)
    encoding = models.CharField(max_length=50, null=True, blank=True)  
    files = models.TextField(null=True, blank=True) 
    upload_date = models.DateTimeField(auto_now_add=True)
    # user = models.ForeignKey(User, on_delete=models.CASCADE)
    length = models.BigIntegerField(null=True)
    piece_length = models.IntegerField(null=True)  # Length of each piece in bytes
    pieces = models.BinaryField(null=True)  # Concatenation of SHA1 hashes of each piece    
    def __str__(self):
        return f"Torrent: {self.info_hash} - {self.announce}"


class Peer(models.Model):
    torrents = models.ManyToManyField(Torrent, related_name='peers')  # Foreign key to the Torrent
    peer_id = models.CharField(max_length=20)  # Peer ID
    ip = models.GenericIPAddressField()  # Peer IP address
    port = models.PositiveIntegerField()  # Peer port number
    last_seen = models.DateTimeField(auto_now=True)  # To track last activity
    left = models.IntegerField() 
    # Process (Seeder if 100%, Leecher if < 100%, calculated by 100*ceil(left/total length))

    def __str__(self):
        return f"({self.ip},{self.port})"
    
    @property
    def is_seeder(self):
        """Determine if the peer is a seeder."""
        return self.left == 0


class Tracker(models.Model):
    tracker_id = models.CharField(max_length=40, unique=True)  # Unique tracker ID
    torrents = models.ManyToManyField(Torrent, related_name='trackers')  # Many-to-many relationship with Torrents
    last_announce = models.DateTimeField(auto_now=True)  # To track last announce time

    def __str__(self):
        return self.tracker_id
    
    

class TorrentInfo(models.Model):
    torrent = models.OneToOneField(Torrent, on_delete=models.CASCADE) 
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    description = models.TextField()
    # update when some one send event = started + shutdown
    seeder = models.PositiveIntegerField(default=0)
    leecher = models.PositiveIntegerField(default=0)

    # update when some one send event = completed
    completed = models.PositiveIntegerField(default=0)


