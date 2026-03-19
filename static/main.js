/**
 * Kildear — main.js
 * Global utilities, post interactions, lazy loading, UI polish.
 * Added WebRTC call functionality
 */

/* ── CSRF Token from meta or inline ──────────────────────────────────────── */
function getCSRF() {
  const m = document.querySelector('meta[name="csrf-token"]');
  return m ? m.content : (window._csrf || '');
}

/* ── Fetch helper with CSRF ───────────────────────────────────────────────── */
async function kFetch(url, opts = {}) {
  const defaults = {
    credentials: 'same-origin',
    headers: {
      'X-CSRFToken': getCSRF(),
      'Content-Type': 'application/json',
      ...opts.headers,
    },
  };

  // Don't set Content-Type for FormData
  if (opts.body instanceof FormData) {
    delete defaults.headers['Content-Type'];
  }

  const res = await fetch(url, { ...defaults, ...opts });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

/* ── Toast notifications ─────────────────────────────────────────────────── */
function toast(msg, type = 'info', duration = 4000) {
  let container = document.getElementById('flashContainer');
  if (!container) {
    container = document.createElement('div');
    container.id = 'flashContainer';
    container.className = 'flash-container';
    document.body.appendChild(container);
  }
  const el = document.createElement('div');
  el.className = `flash flash-${type}`;
  const icons = { success: 'circle-check', error: 'circle-xmark', info: 'circle-info', warning: 'triangle-exclamation' };
  el.innerHTML = `<i class="fa-solid fa-${icons[type] || 'circle-info'}"></i> ${msg}`;
  el.style.cursor = 'pointer';
  el.onclick = () => el.remove();
  container.appendChild(el);
  setTimeout(() => el.remove(), duration);
}

/* ── Call Management ─────────────────────────────────────────────────────── */
class CallManager {
  constructor() {
    this.peerConnection = null;
    this.localStream = null;
    this.remoteStream = null;
    this.currentCall = null;
    this.callType = null;
    this.room = null;
    this.isMuted = false;
    this.isVideoEnabled = true;

    // STUN servers for WebRTC
    this.iceServers = {
      iceServers: [
        { urls: 'stun:stun.l.google.com:19302' },
        { urls: 'stun:stun1.l.google.com:19302' }
      ]
    };
  }

  async startCall(partnerId, partnerUsername, type = 'audio') {
    try {
      // Request media permissions
      const constraints = {
        audio: true,
        video: type === 'video'
      };

      this.localStream = await navigator.mediaDevices.getUserMedia(constraints);
      this.callType = type;

      // Display local video
      this.showLocalVideo();

      // Initialize peer connection
      this.peerConnection = new RTCPeerConnection(this.iceServers);

      // Add local stream to connection
      this.localStream.getTracks().forEach(track => {
        this.peerConnection.addTrack(track, this.localStream);
      });

      // Handle incoming tracks
      this.peerConnection.ontrack = (event) => {
        this.remoteStream = event.streams[0];
        this.showRemoteVideo();
      };

      // Handle ICE candidates
      this.peerConnection.onicecandidate = (event) => {
        if (event.candidate) {
          socket.emit('webrtc_ice_candidate', {
            room: this.room,
            candidate: event.candidate
          });
        }
      };

      // Create offer
      const offer = await this.peerConnection.createOffer();
      await this.peerConnection.setLocalDescription(offer);

      // Start call on server
      const response = await kFetch('/call/start', {
        method: 'POST',
        body: JSON.stringify({
          callee_id: partnerId,
          type: type
        })
      });

      if (response.success) {
        this.currentCall = response.call_id;
        this.room = [currentUserId, partnerId].sort().join('_');

        // Send offer via signaling
        socket.emit('webrtc_offer', {
          room: this.room,
          offer: offer
        });

        toast(`Calling ${partnerUsername}...`, 'info');
        this.showCallModal('outgoing', partnerUsername);
      }
    } catch (error) {
      console.error('Error starting call:', error);
      toast('Could not start call. Please check permissions.', 'error');
    }
  }

  async acceptCall(offer, callerId, callerUsername, type) {
    try {
      const constraints = {
        audio: true,
        video: type === 'video'
      };

      this.localStream = await navigator.mediaDevices.getUserMedia(constraints);
      this.callType = type;

      this.showLocalVideo();

      this.peerConnection = new RTCPeerConnection(this.iceServers);

      this.localStream.getTracks().forEach(track => {
        this.peerConnection.addTrack(track, this.localStream);
      });

      this.peerConnection.ontrack = (event) => {
        this.remoteStream = event.streams[0];
        this.showRemoteVideo();
      };

      this.peerConnection.onicecandidate = (event) => {
        if (event.candidate) {
          socket.emit('webrtc_ice_candidate', {
            room: this.room,
            candidate: event.candidate
          });
        }
      };

      await this.peerConnection.setRemoteDescription(new RTCSessionDescription(offer));
      const answer = await this.peerConnection.createAnswer();
      await this.peerConnection.setLocalDescription(answer);

      socket.emit('webrtc_answer', {
        room: this.room,
        answer: answer
      });

      // Accept call on server
      await kFetch(`/call/${this.currentCall}/accept`, {
        method: 'POST'
      });

      this.showCallModal('connected', callerUsername);
    } catch (error) {
      console.error('Error accepting call:', error);
      toast('Could not accept call.', 'error');
    }
  }

  async endCall() {
    if (this.peerConnection) {
      this.peerConnection.close();
      this.peerConnection = null;
    }

    if (this.localStream) {
      this.localStream.getTracks().forEach(track => track.stop());
      this.localStream = null;
    }

    if (this.currentCall) {
      await kFetch(`/call/${this.currentCall}/end`, {
        method: 'POST'
      });
      this.currentCall = null;
    }

    this.hideCallModal();
    toast('Call ended', 'info');
  }

  toggleMute() {
    if (this.localStream) {
      const audioTracks = this.localStream.getAudioTracks();
      audioTracks.forEach(track => {
        track.enabled = !track.enabled;
      });
      this.isMuted = !this.isMuted;

      const muteBtn = document.getElementById('muteBtn');
      if (muteBtn) {
        muteBtn.innerHTML = this.isMuted ?
          '<i class="fa-solid fa-microphone-slash"></i>' :
          '<i class="fa-solid fa-microphone"></i>';
      }
    }
  }

  toggleVideo() {
    if (this.localStream && this.callType === 'video') {
      const videoTracks = this.localStream.getVideoTracks();
      videoTracks.forEach(track => {
        track.enabled = !track.enabled;
      });
      this.isVideoEnabled = !this.isVideoEnabled;

      const videoBtn = document.getElementById('videoBtn');
      if (videoBtn) {
        videoBtn.innerHTML = this.isVideoEnabled ?
          '<i class="fa-solid fa-video"></i>' :
          '<i class="fa-solid fa-video-slash"></i>';
      }
    }
  }

  showLocalVideo() {
    let localVideo = document.getElementById('localVideo');
    if (!localVideo) {
      const videoContainer = document.createElement('div');
      videoContainer.id = 'localVideoContainer';
      videoContainer.innerHTML = `
        <video id="localVideo" autoplay muted playsinline></video>
      `;
      document.body.appendChild(videoContainer);
      localVideo = document.getElementById('localVideo');
    }
    localVideo.srcObject = this.localStream;
  }

  showRemoteVideo() {
    let remoteVideo = document.getElementById('remoteVideo');
    if (!remoteVideo) {
      const videoContainer = document.createElement('div');
      videoContainer.id = 'remoteVideoContainer';
      videoContainer.innerHTML = `
        <video id="remoteVideo" autoplay playsinline></video>
      `;
      document.body.appendChild(videoContainer);
      remoteVideo = document.getElementById('remoteVideo');
    }
    remoteVideo.srcObject = this.remoteStream;
  }

  showCallModal(type, username) {
    let modal = document.getElementById('callModal');
    if (!modal) {
      modal = document.createElement('div');
      modal.id = 'callModal';
      modal.className = 'call-modal';
      modal.innerHTML = `
        <div class="call-modal-content">
          <div class="call-avatar">
            <img src="" alt="User" id="callAvatar">
          </div>
          <div class="call-info">
            <h3 id="callUsername"></h3>
            <p id="callStatus"></p>
            <div id="callDuration">00:00</div>
          </div>
          <div class="call-controls">
            <button class="call-btn mute" id="muteBtn" onclick="callManager.toggleMute()">
              <i class="fa-solid fa-microphone"></i>
            </button>
            ${this.callType === 'video' ? `
              <button class="call-btn video" id="videoBtn" onclick="callManager.toggleVideo()">
                <i class="fa-solid fa-video"></i>
              </button>
            ` : ''}
            <button class="call-btn end-call" onclick="callManager.endCall()">
              <i class="fa-solid fa-phone"></i>
            </button>
          </div>
        </div>
      `;
      document.body.appendChild(modal);
    }

    document.getElementById('callUsername').textContent = username;
    document.getElementById('callAvatar').src = document.querySelector('.chat-partner-avatar img')?.src || '/static/default_avatar.png';
    document.getElementById('callStatus').textContent = type === 'outgoing' ? 'Calling...' : 'Connected';
    modal.classList.add('active');
  }

  hideCallModal() {
    const modal = document.getElementById('callModal');
    if (modal) {
      modal.classList.remove('active');
    }

    const localContainer = document.getElementById('localVideoContainer');
    const remoteContainer = document.getElementById('remoteVideoContainer');
    if (localContainer) localContainer.remove();
    if (remoteContainer) remoteContainer.remove();
  }
}

// Initialize call manager
const callManager = new CallManager();

// Socket.io event handlers for calls
if (typeof socket !== 'undefined') {
  socket.on('incoming_call', async (data) => {
    if (confirm(`Incoming ${data.type} call from ${data.caller_username}. Accept?`)) {
      callManager.room = [currentUserId, data.caller_id].sort().join('_');
      callManager.currentCall = data.call_id;
      await callManager.acceptCall(data.offer, data.caller_id, data.caller_username, data.type);
    } else {
      // Reject call
      await kFetch(`/call/${data.call_id}/reject`, { method: 'POST' });
    }
  });

  socket.on('webrtc_offer', async (data) => {
    if (!callManager.peerConnection) {
      callManager.room = data.room;
      // Show incoming call UI
      showIncomingCallModal(data);
    }
  });

  socket.on('webrtc_answer', async (data) => {
    if (callManager.peerConnection) {
      await callManager.peerConnection.setRemoteDescription(
        new RTCSessionDescription(data.answer)
      );
    }
  });

  socket.on('webrtc_ice_candidate', async (data) => {
    if (callManager.peerConnection) {
      await callManager.peerConnection.addIceCandidate(
        new RTCIceCandidate(data.candidate)
      );
    }
  });

  socket.on('call_accepted', (data) => {
    toast('Call accepted!', 'success');
    callManager.showCallModal('connected', document.getElementById('callUsername').textContent);
  });

  socket.on('call_rejected', (data) => {
    toast('Call rejected', 'info');
    callManager.endCall();
  });

  socket.on('call_ended', (data) => {
    toast('Call ended', 'info');
    callManager.endCall();
  });
}

/* ── Like a post ─────────────────────────────────────────────────────────── */
async function likePost(postId) {
  try {
    const data = await kFetch(`/post/${postId}/like`, { method: 'POST' });
    const btn   = document.getElementById(`like-btn-${postId}`);
    const count = document.getElementById(`like-count-${postId}`);
    if (btn) {
      btn.classList.toggle('liked', data.liked);
      const icon = btn.querySelector('i');
      if (icon) icon.className = data.liked ? 'fa-solid fa-heart' : 'fa-regular fa-heart';
    }
    if (count) count.textContent = data.count;
  } catch (e) {
    toast('Could not process like.', 'error');
  }
}

/* ── Follow / Unfollow ───────────────────────────────────────────────────── */
async function followUser(username, btn) {
  try {
    const data = await kFetch(`/follow/${username}`, { method: 'POST' });
    if (btn) {
      if (data.following) {
        btn.textContent = '✓ Following';
        btn.classList.add('following');
      } else {
        btn.textContent = '+ Follow';
        btn.classList.remove('following');
      }
    }
    const fc = document.getElementById('follower-count');
    if (fc) fc.textContent = data.followers;
  } catch (e) {
    toast('Could not update follow status.', 'error');
  }
}

/* ── Comment form (AJAX) ─────────────────────────────────────────────────── */
function initCommentForm(postId) {
  const form = document.getElementById(`comment-form-${postId}`);
  if (!form) return;
  form.addEventListener('submit', async e => {
    e.preventDefault();
    const fd = new FormData(form);
    try {
      const data = await kFetch(`/post/${postId}/comment`, { method: 'POST', body: fd });
      if (data.id) {
        const list = document.getElementById(`comments-list-${postId}`);
        if (list) {
          const el = buildCommentEl(data);
          list.appendChild(el);
        }
        form.reset();
        const cnt = document.getElementById(`comment-count-${postId}`);
        if (cnt) cnt.textContent = parseInt(cnt.textContent || 0) + 1;
      } else {
        toast(data.error || 'Failed to post comment.', 'error');
      }
    } catch(err) {
      toast('Failed to post comment.', 'error');
    }
  });
}

function buildCommentEl(data) {
  const el = document.createElement('div');
  el.className = 'comment-item';
  el.id = `comment-${data.id}`;
  el.innerHTML = `
    <img src="${data.avatar}" class="avatar avatar-xs" alt="${data.username}"/>
    <div class="comment-body">
      <span class="comment-username">@${data.username}</span>
      <span class="comment-text">${escHtml(data.content)}</span>
      <span class="comment-time">${data.created_at}</span>
    </div>`;
  el.style.animation = 'msgIn 0.25s ease';
  return el;
}

/* ── XSS sanitizer ───────────────────────────────────────────────────────── */
function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/* ── Post creation form preview ─────────────────────────────────────────── */
function initPostForm() {
  const form    = document.getElementById('post-form');
  const preview = document.getElementById('media-preview');
  const input   = document.getElementById('post-media-input');
  if (!input || !preview) return;

  // Show "file" label to trigger input
  document.querySelectorAll('[data-trigger-file]').forEach(btn => {
    btn.addEventListener('click', () => input.click());
  });

  input.addEventListener('change', () => {
    const file = input.files[0];
    if (!file) { preview.innerHTML = ''; preview.style.display = 'none'; return; }
    const url = URL.createObjectURL(file);
    const isVideo = file.type.startsWith('video/');
    preview.innerHTML = isVideo
      ? `<video src="${url}" controls style="max-width:100%;max-height:280px;border-radius:10px;"></video>`
      : `<img src="${url}" style="max-width:100%;max-height:280px;border-radius:10px;object-fit:cover;"/>`;
    preview.style.display = 'block';
    // Clear btn
    const clrBtn = document.createElement('button');
    clrBtn.type = 'button';
    clrBtn.className = 'btn btn-sm btn-danger';
    clrBtn.style.marginTop = '8px';
    clrBtn.innerHTML = '<i class="fa-solid fa-xmark"></i> Remove';
    clrBtn.onclick = () => {
      input.value = '';
      preview.innerHTML = '';
      preview.style.display = 'none';
    };
    preview.appendChild(clrBtn);
  });

  // Auto-resize textarea
  const ta = document.getElementById('post-content');
  if (ta) {
    ta.addEventListener('input', () => {
      ta.style.height = 'auto';
      ta.style.height = Math.min(ta.scrollHeight, 200) + 'px';
    });
  }
}

/* ── Character counter ───────────────────────────────────────────────────── */
function initCharCounter(inputId, counterId, max) {
  const input   = document.getElementById(inputId);
  const counter = document.getElementById(counterId);
  if (!input || !counter) return;
  const update = () => {
    const remaining = max - input.value.length;
    counter.textContent = remaining;
    counter.style.color = remaining < 20 ? 'var(--warning)'
                        : remaining < 0   ? 'var(--danger)'
                        :                   'var(--text-dim)';
  };
  input.addEventListener('input', update);
  update();
}

/* ── Infinite scroll helper ──────────────────────────────────────────────── */
function initInfiniteScroll(containerSel, nextUrl, itemRenderer) {
  const container = document.querySelector(containerSel);
  if (!container || !nextUrl) return;
  let loading = false;
  let url = nextUrl;

  const observer = new IntersectionObserver(async entries => {
    if (!entries[0].isIntersecting || loading || !url) return;
    loading = true;
    try {
      const res  = await fetch(url + (url.includes('?') ? '&' : '?') + 'ajax=1');
      const data = await res.json();
      data.items.forEach(item => container.appendChild(itemRenderer(item)));
      url = data.next_url || null;
    } catch(e) { /* silent fail */ }
    loading = false;
  }, { rootMargin: '200px' });

  const sentinel = document.createElement('div');
  sentinel.className = 'scroll-sentinel';
  container.parentNode.insertBefore(sentinel, container.nextSibling);
  observer.observe(sentinel);
}

/* ── Lazy-load images ────────────────────────────────────────────────────── */
function initLazyImages() {
  if (!('IntersectionObserver' in window)) return;
  const obs = new IntersectionObserver(entries => {
    entries.forEach(e => {
      if (!e.isIntersecting) return;
      const img = e.target;
      if (img.dataset.src) { img.src = img.dataset.src; delete img.dataset.src; }
      obs.unobserve(img);
    });
  }, { rootMargin: '300px' });
  document.querySelectorAll('img[data-src]').forEach(img => obs.observe(img));
}

/* ── Share post ──────────────────────────────────────────────────────────── */
function sharePost(postId) {
  const url = `${window.location.origin}/post/${postId}`;
  if (navigator.share) {
    navigator.share({ url, title: 'Check this post on Kildear' }).catch(() => {});
  } else {
    navigator.clipboard.writeText(url)
      .then(() => toast('Link copied to clipboard!', 'success'))
      .catch(() => toast('Could not copy link.', 'error'));
  }
}

/* ── Delete post confirmation ────────────────────────────────────────────── */
function confirmDeletePost(postId) {
  if (!confirm('Delete this post? This cannot be undone.')) return;
  const form = document.createElement('form');
  form.method = 'POST';
  form.action = `/post/${postId}/delete`;
  const csrf = document.createElement('input');
  csrf.type  = 'hidden';
  csrf.name  = 'csrf_token';
  csrf.value = getCSRF();
  form.appendChild(csrf);
  document.body.appendChild(form);
  form.submit();
}

/* ── Subscribe / unsubscribe channel ─────────────────────────────────────── */
async function toggleSubscribe(slug, btn) {
  try {
    const data = await kFetch(`/channels/${slug}/subscribe`, { method: 'POST' });
    if (btn) {
      btn.textContent = data.subscribed ? '✓ Subscribed' : '+ Subscribe';
    }
    const sc = document.getElementById('sub-count');
    if (sc) sc.textContent = data.count;
  } catch(e) {
    toast('Failed to update subscription.', 'error');
  }
}

/* ── Block / unblock user ────────────────────────────────────────────────── */
async function blockUser(userId) {
  if (!confirm('Are you sure you want to block this user?')) return;
  try {
    const data = await kFetch(`/user/${userId}/block`, { method: 'POST' });
    if (data.success) {
      toast('User blocked', 'success');
      location.reload();
    }
  } catch(e) {
    toast('Failed to block user.', 'error');
  }
}

async function unblockUser(userId) {
  try {
    const data = await kFetch(`/user/${userId}/unblock`, { method: 'POST' });
    if (data.success) {
      toast('User unblocked', 'success');
      location.reload();
    }
  } catch(e) {
    toast('Failed to unblock user.', 'error');
  }
}

/* ── Theme color picker (profile edit) ──────────────────────────────────── */
function initColorPicker() {
  const picker = document.getElementById('accent-color-picker');
  const preview= document.getElementById('color-preview');
  if (!picker) return;
  picker.addEventListener('input', () => {
    if (preview) preview.style.background = picker.value;
    document.documentElement.style.setProperty('--primary', picker.value);
  });
}

/* ── Image upload drag & drop ────────────────────────────────────────────── */
function initDropZone(zoneId, inputId) {
  const zone  = document.getElementById(zoneId);
  const input = document.getElementById(inputId);
  if (!zone || !input) return;

  ['dragenter','dragover'].forEach(ev => {
    zone.addEventListener(ev, e => {
      e.preventDefault();
      zone.classList.add('drag-over');
    });
  });
  ['dragleave','drop'].forEach(ev => {
    zone.addEventListener(ev, e => {
      e.preventDefault();
      zone.classList.remove('drag-over');
    });
  });
  zone.addEventListener('drop', e => {
    const files = e.dataTransfer.files;
    if (files.length) {
      const dt = new DataTransfer();
      dt.items.add(files[0]);
      input.files = dt.files;
      input.dispatchEvent(new Event('change'));
    }
  });
  zone.addEventListener('click', () => input.click());
}

/* ── Time ago formatter ──────────────────────────────────────────────────── */
function timeAgo(dateStr) {
  const now  = new Date();
  const then = new Date(dateStr);
  const secs = Math.floor((now - then) / 1000);
  if (secs < 60)  return 'just now';
  if (secs < 3600)  return `${Math.floor(secs/60)}m ago`;
  if (secs < 86400) return `${Math.floor(secs/3600)}h ago`;
  if (secs < 604800)return `${Math.floor(secs/86400)}d ago`;
  return then.toLocaleDateString();
}

/* ── Live relative timestamps ────────────────────────────────────────────── */
function initRelativeTimes() {
  document.querySelectorAll('[data-time]').forEach(el => {
    el.textContent = timeAgo(el.dataset.time);
  });
}

/* ── Keyboard shortcuts ──────────────────────────────────────────────────── */
document.addEventListener('keydown', e => {
  // Ctrl+K / Cmd+K → focus search
  if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
    e.preventDefault();
    const s = document.querySelector('input[name="q"]');
    if (s) s.focus();
  }
  // Esc → close modals / overlays
  if (e.key === 'Escape') {
    document.querySelectorAll('.modal.open, .media-overlay.open, .call-modal.active').forEach(el => {
      el.classList.remove('open', 'active');
    });
    document.body.style.overflow = '';

    // End call if active
    if (callManager.currentCall) {
      callManager.endCall();
    }
  }
});

/* ── Smooth page transitions ─────────────────────────────────────────────── */
function initPageTransitions() {
  document.querySelectorAll('a[href]').forEach(a => {
    if (a.href && a.href.startsWith(window.location.origin)
        && !a.target && !a.download) {
      a.addEventListener('click', e => {
        if (e.metaKey || e.ctrlKey || e.shiftKey) return;
        document.body.style.opacity = '0.6';
        document.body.style.transition = 'opacity 0.15s ease';
      });
    }
  });
  window.addEventListener('pageshow', () => {
    document.body.style.opacity = '1';
  });
}

/* ── Modal helpers ───────────────────────────────────────────────────────── */
function openModal(id) {
  const m = document.getElementById(id);
  if (m) {
    m.classList.add('open');
    document.body.style.overflow = 'hidden';
  }
}
function closeModal(id) {
  const m = document.getElementById(id);
  if (m) {
    m.classList.remove('open');
    document.body.style.overflow = '';
  }
}

/* ── Notification badge update via polling ───────────────────────────────── */
let _notifTimer = null;
function startNotifPolling(intervalMs = 30000) {
  async function poll() {
    try {
      const data = await kFetch('/api/unread_counts');
      const nb = document.querySelector('.nav-item[href="/notifications"] .nav-badge');
      const mb = document.querySelector('.nav-item[href="/chat"] .nav-badge');
      if (nb) { nb.textContent = data.notifications; nb.style.display = data.notifications > 0 ? '' : 'none'; }
      if (mb) { mb.textContent = data.messages;     mb.style.display = data.messages > 0 ? '' : 'none'; }
    } catch(e) { /* silent */ }
  }
  poll();
  _notifTimer = setInterval(poll, intervalMs);
}

/* ── Initialize everything on DOM ready ─────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  initPostForm();
  initLazyImages();
  initRelativeTimes();
  initColorPicker();
  initPageTransitions();
  initCharCounter('post-content', 'post-char-count', 2000);

  // Drop zones
  initDropZone('avatar-drop', 'avatar-input');
  initDropZone('cover-drop',  'cover-input');

  // Init comment forms
  document.querySelectorAll('[id^="comment-form-"]').forEach(form => {
    const id = form.id.replace('comment-form-', '');
    initCommentForm(id);
  });

  // Auto-dismiss flashes after 5s
  setTimeout(() => {
    document.querySelectorAll('.flash').forEach(f => f.remove());
  }, 5000);

  // Start notification polling
  startNotifPolling();
});