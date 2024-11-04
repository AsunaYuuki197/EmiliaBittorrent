from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.decorators import login_required
from django.contrib.admin.views.decorators import staff_member_required
from django.core.mail import send_mail
from django.contrib import messages
from django.db.models import Avg
from django.http import HttpResponse, HttpResponseForbidden
from django.core.paginator import Paginator
import ipaddress
import random
import bencodepy

from .process_function import *
from .forms import *
from .models import *

def register(request):
    if request.method == 'POST':
        form = SignUpForm(request.POST)
        if form.is_valid():
            user = form.save()
            login(request, user)
            return redirect('home')
    else:
        form = SignUpForm()
    return render(request, 'register.html', {'form': form})


def login_view(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('home')
    return render(request, 'login.html')


def logout_view(request):
    logout(request)
    return redirect('home')
    

def home(request):
    # Get infomartion of torrent to display 
    torrent_stats = TorrentInfo.objects.prefetch_related('torrent').all()
    paginator = Paginator(torrent_stats, 10)  # Show 10 objects per page
    page_number = request.GET.get('page')  # Get the current page number from the request
    page_torrent_stats = paginator.get_page(page_number)  # Get the page object

    return render(request, 'home.html', {'torrent_stats': page_torrent_stats})




@login_required(login_url='login') 
def upload_torrent(request):
    if request.method == 'POST':
        torrent_file_form = TorrentFileUploadForm(request.POST, request.FILES)
        torrent_info_form = TorrentInfoForm(request.POST)

        if torrent_file_form.is_valid() and 'torrent_file' in request.FILES:
            
            torrent_data = get_metadata(request.FILES['torrent_file'])
            # Populate Torrent and Info forms with parsed data
            torrent = Torrent.objects.create()

            torrent.name= torrent_data['name']
            torrent.info_hash= torrent_data['info_hash']
            torrent.announce= torrent_data['announce']
            torrent.files= torrent_data['files']
            torrent.piece_length= torrent_data['piece_length'] 
            torrent.pieces= torrent_data['pieces']
            torrent.length= torrent_data['length']

            # if all([torrent_form.is_valid(), torrent_info_form.is_valid()]):
            if torrent_info_form.is_valid():
                file = request.FILES['torrent_file']  # Save the .torrent file
                file.seek(0)
                filename = f"torrents/{file}"
                torrent.torrent_file = request.FILES['torrent_file']   
                torrent.torrent_url = upload_to_firebase(file, filename)    
                torrent.save()

                torrent_info = torrent_info_form.save(commit=False)
                torrent_info.torrent = torrent
                torrent_info.user = request.user
                torrent_info.save()

                return redirect('home')  
    else:
        torrent_file_form = TorrentFileUploadForm()
        torrent_info_form = TorrentInfoForm()

    context = {
        'torrent_file_form': torrent_file_form,
        'torrent_info_form': torrent_info_form
    }
    return render(request, 'upload_torrent.html', context)

@login_required
def manage_torrent(request):
    # Staff members can view all torrents; regular users can view only their own
    if request.user.is_staff:
        torrents = TorrentInfo.objects.all()
    else:
        torrents = TorrentInfo.objects.filter(user=request.user)

    context = {
        'torrents': torrents
    }
    return render(request, 'manage_torrents.html', context)

@login_required
def delete_torrent(request, id):
    torrent = get_object_or_404(Torrent, pk=id)

    # Allow deletion if the user is staff or the uploader of the torrent
    if request.user.is_staff or torrent.torrentinfo.user == request.user:
        torrent.delete()
        messages.success(request, 'Torrent deleted successfully.')
    else:
        return HttpResponseForbidden("You don't have permission to delete this torrent.")

    return redirect('manage_torrent')  # Redirect to the torrent management page


@login_required
@staff_member_required
def manage_user(request):
    users = User.objects.all()
    return render(request, 'manage_users.html', {'users': users})

@login_required
@staff_member_required
def delete_user(request, id):
    user = get_object_or_404(User, id=id)
    user.delete()
    return redirect('manage_user')

@login_required
@staff_member_required
def delete_user(request, id):
    user = get_object_or_404(User, id=id)
    user.delete()
    return redirect('manage_user')

@login_required
@staff_member_required
def edit_user(request, id):
    user = get_object_or_404(User, id=id)
    if request.method == 'POST':
        user.username = request.POST.get('username')
        user.email = request.POST.get('email')
        user.password = request.POST.get('password')
        user.is_staff = 'is_staff' in request.POST  # Checkbox for staff status
        user.save()
        return redirect('manage_user')
    return render(request, 'edit_user.html', {'user': user})


@login_required
@staff_member_required
def view_stats(request):
    # Fetch all peers and their associated torrents
    peers = Peer.objects.prefetch_related('torrents').all()

    # Prepare data to send to the template
    peer_data = []
    for peer in peers:
        for torrent in peer.torrents.all():
            progress = (torrent.length - peer.left) / torrent.length * 100 if torrent.length > 0 else 0
            peer_data.append({
                'peer_id': peer.peer_id,
                'ip_address': peer.ip,
                'port': peer.port,
                'torrent_name': torrent.name,
                'progress': progress,
                'torrent_length': torrent.length,
                'left': peer.left,
                'torrent_id': torrent.id,
            })

    context = {
        'peer_data': peer_data,
    }
    return render(request, 'view_stats.html', context)


def disconnect_peer(request, peer_id, torrent_id):
    try:
        peer = Peer.objects.get(peer_id=peer_id)
        torrent = Torrent.objects.get(pk=torrent_id)

        peer.torrents.remove(torrent)
        print(peer)
        print(peer.torrents.count())
        if peer.torrents.count() == 0:
            peer.delete()

        return redirect('view_stats')  
    except Peer.DoesNotExist:
        return redirect('view_stats') 
    except TorrentInfo.DoesNotExist:
        return redirect('view_stats') 
    

def torrent_details(request, info_hash):
    torrent = get_object_or_404(Torrent.objects.prefetch_related('torrentinfo'), info_hash=info_hash)
    file_tree = display_subfiles(torrent.files)
    return render(request, 'torrent_detail.html', {'torrent': torrent, 'file_tree': file_tree})



def search_torrent(request):
    # Get the search query from the request
    search_query = request.GET.get('search', '')
    # Filter objects based on the search query
    if search_query:
        object_list = TorrentInfo.objects.filter(torrent__name__icontains=search_query)
    else:
        object_list = TorrentInfo.objects.all()
    

    # Set up pagination
    paginator = Paginator(object_list, 10)  
    page_number = request.GET.get('page')  
    page_torrent_stats = paginator.get_page(page_number)

    return render(request, 'home.html', {'torrent_stats': page_torrent_stats, 'search_query': search_query})


def announce(request):
    try:
        # Parse parameters
        peer_ip = request.META['REMOTE_ADDR']

        info_hash = request.GET.get("info_hash")
        peer_id = request.GET.get("peer_id")
        port = int(request.GET.get("port"))
        uploaded = int(request.GET.get("uploaded", 0))
        downloaded = int(request.GET.get("downloaded", 0))
        left = int(request.GET.get("left", 0))
        compact = int(request.GET.get("compact", 0))
        event = request.GET.get("event", "")
        # Get Torrent object
        torrent = get_object_or_404(Torrent, info_hash=info_hash)
        torrent_info = get_object_or_404(TorrentInfo, torrent=torrent)
        
        def track_event():
            # check or create new peer, peer_id is associated to many torrent
            peer, peer_created = Peer.objects.get_or_create(peer_id=peer_id, defaults={'ip': peer_ip, 'port': port, 'left': left})

            if torrent not in peer.torrents.all():
                # If not, add torrent to peer
                peer.torrents.add(torrent)            

            if event == "started":
                if peer_created:
                    # Peer new, increase the leecher
                    torrent_info.leecher += 1
                # Peer exists, don't increase leecher
            elif event == "completed" and left == 0:
                if peer_created:
                    # Peer new, don't decrease leecher
                    torrent_info.completed += 1
                    torrent_info.seeder += 1
                elif torrent_info.leecher > 0:
                    # Peer exist, decrease leecher
                    torrent_info.leecher -= 1

            elif event == "stopped":
                if not peer_created:
                    # Peer exists, remove relationship between peer and torrent from db
                    if left == 0 and torrent_info.seeder > 0:  # peer was a seeder
                        torrent_info.seeder -= 1
                    elif torrent_info.seeder > 0:  # peer was a leecher
                        torrent_info.leecher -= 1

                    peer.torrents.remove(torrent)
                    # if dont have any relationship remove peer
                    if peer.torrents.count() == 0:
                        peer.delete()
                # peer is new, don't decrease leecher or seeder counts
                else:
                    peer.delete()

            # Save the torrent_info changes
            torrent_info.save()
        
        track_event()

        # Query peers for this torrent
        peers = torrent.peers.exclude(ip=peer_ip)[:50]
        
        # Prepare peer list for response
        if compact:
            peers_data = b"".join([
                ipaddress.ip_address(peer.ip).packed + peer.port.to_bytes(2, 'big')
                for peer in peers
            ])
        else:
            peers_data = [{"peer_id": peer.peer_id, "ip": peer.ip, "port": peer.port} for peer in peers]
        
        # Create response dictionary
        response_dict = {
            "interval": 10,
            "complete": torrent_info.seeder,
            "incomplete": torrent_info.leecher,
            "peers": peers_data
        }
        print(response_dict)
        # Bencode the response 
        response = bencodepy.encode(response_dict)
        return HttpResponse(response, content_type="text/plain")
    
    except Exception as e:
        error_response = {"failure reason": str(e)}
        return HttpResponse(bencodepy.encode(error_response), content_type="text/plain")



def test(request):
    return redirect('home')  

