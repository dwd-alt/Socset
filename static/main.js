/**
 * Kildear — main.js
 * Complete JavaScript with voice messages, calls, admin features
 */

/* ── CSRF Token ──────────────────────────────────────────────────────────── */
function getCSRF() {
    const m = document.querySelector('meta[name="csrf-token"]');
    return m ? m.content : (window._csrf || '');
}

/* ── Fetch helper ────────────────────────────────────────────────────────── */
async function kFetch(url, opts = {}) {
    const defaults = {
        credentials: 'same-origin',
        headers: {
            'X-CSRFToken': getCSRF(),
            'Content-Type': 'application/json',
            ...opts.headers,
        },
    };

    if (opts.body instanceof FormData) {
        delete defaults.headers['Content-Type'];
    }

    try {
        const res = await fetch(url, { ...defaults, ...opts });
        if (!res.ok) throw new Error(`HTTP ${res.status}`);
        return await res.json();
    } catch (error) {
        console.error('Fetch error:', error);
        throw error;
    }
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
    const icons = {
        success: 'circle-check',
        error: 'circle-xmark',
        info: 'circle-info',
        warning: 'triangle-exclamation'
    };
    el.innerHTML = `<i class="fa-solid fa-${icons[type] || 'circle-info'}"></i> ${msg}`;
    el.style.cursor = 'pointer';
    el.onclick = () => el.remove();
    container.appendChild(el);
    setTimeout(() => el.remove(), duration);
}

/* ── Call Manager ────────────────────────────────────────────────────────── */
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

        this.iceServers = {
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' },
                { urls: 'stun:stun2.l.google.com:19302' },
                { urls: 'stun:stun3.l.google.com:19302' },
                { urls: 'stun:stun4.l.google.com:19302' }
            ]
        };
    }

    async startCall(partnerId, partnerUsername, type = 'audio') {
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

            const offer = await this.peerConnection.createOffer();
            await this.peerConnection.setLocalDescription(offer);

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

/* ── Voice Message Recorder ──────────────────────────────────────────────── */
class VoiceRecorder {
    constructor() {
        this.mediaRecorder = null;
        this.audioChunks = [];
        this.isRecording = false;
        this.stream = null;
        this.recordingTimer = null;
        this.recordingDuration = 0;
        this.onComplete = null;
    }

    async startRecording() {
        try {
            this.stream = await navigator.mediaDevices.getUserMedia({ audio: true });
            this.mediaRecorder = new MediaRecorder(this.stream);
            this.audioChunks = [];
            this.recordingDuration = 0;

            this.mediaRecorder.ondataavailable = event => {
                this.audioChunks.push(event.data);
            };

            this.mediaRecorder.onstop = () => {
                const audioBlob = new Blob(this.audioChunks, { type: 'audio/webm' });
                if (this.onComplete) {
                    this.onComplete(audioBlob, this.recordingDuration);
                }
                this.stream.getTracks().forEach(track => track.stop());
            };

            this.mediaRecorder.start();
            this.isRecording = true;

            // Start timer
            this.recordingTimer = setInterval(() => {
                this.recordingDuration++;
                this.updateRecordingDisplay();
            }, 1000);

            return true;
        } catch (error) {
            console.error('Error starting recording:', error);
            toast('Could not access microphone', 'error');
            return false;
        }
    }

    stopRecording() {
        if (this.mediaRecorder && this.isRecording) {
            this.mediaRecorder.stop();
            this.isRecording = false;
            clearInterval(this.recordingTimer);
        }
    }

    cancelRecording() {
        if (this.mediaRecorder && this.isRecording) {
            this.mediaRecorder.stop();
            this.isRecording = false;
            clearInterval(this.recordingTimer);
            this.audioChunks = [];
            this.stream.getTracks().forEach(track => track.stop());
        }
    }

    updateRecordingDisplay() {
        const minutes = Math.floor(this.recordingDuration / 60);
        const seconds = this.recordingDuration % 60;
        const display = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;

        const timerEl = document.getElementById('voiceTimer');
        if (timerEl) timerEl.textContent = display;
    }
}

/* ── Initialize global objects ───────────────────────────────────────────── */
const callManager = new CallManager();
const voiceRecorder = new VoiceRecorder();

/* ── Socket.IO setup ─────────────────────────────────────────────────────── */
let socket = null;

function initSocketIO() {
    if (typeof io === 'undefined') {
        console.error('Socket.IO not loaded');
        return;
    }

    socket = io();

    socket.on('connect', () => {
        console.log('Socket.IO connected');
        socket.emit('join_user_room');
    });

    socket.on('new_notification', (data) => {
        updateNotificationBadge();
        showToast(data.text, 'info');
        playNotificationSound();
    });

    socket.on('new_message', (data) => {
        updateMessageBadge();
        const currentChatPartner = document.getElementById('partnerUsername')?.value;
        if (currentChatPartner !== data.sender_username) {
            showToast(`New message from ${data.sender_username}`, 'info');
        }
    });

    socket.on('new_voice_message', (data) => {
        updateVoiceBadge();
        const currentChatPartner = document.getElementById('partnerUsername')?.value;
        if (currentChatPartner !== data.sender_username) {
            showToast(`Voice message from ${data.sender_username}`, 'info');
        }
        if (typeof appendVoiceMessage === 'function') {
            appendVoiceMessage(data);
        }
    });

    socket.on('incoming_call', async (data) => {
        if (confirm(`Incoming ${data.type} call from ${data.caller_username}. Accept?`)) {
            callManager.room = [currentUserId, data.caller_id].sort().join('_');
            callManager.currentCall = data.call_id;
            await callManager.acceptCall(data.offer, data.caller_id, data.caller_username, data.type);
        } else {
            await kFetch(`/call/${data.call_id}/reject`, { method: 'POST' });
        }
    });

    socket.on('call_accepted', () => {
        toast('Call accepted!', 'success');
        callManager.showCallModal('connected', document.getElementById('callUsername')?.textContent || '');
    });

    socket.on('call_rejected', () => {
        toast('Call rejected', 'info');
        callManager.endCall();
    });

    socket.on('call_ended', () => {
        toast('Call ended', 'info');
        callManager.endCall();
    });
}

/* ── Badge updates ───────────────────────────────────────────────────────── */
async function updateNotificationBadge() {
    try {
        const data = await kFetch('/api/unread_counts');
        const badge = document.querySelector('.nav-item[href="/notifications"] .nav-badge');
        if (badge) {
            if (data.notifications > 0) {
                badge.textContent = data.notifications;
                badge.style.display = 'inline';
            } else {
                badge.style.display = 'none';
            }
        }
    } catch (error) {
        console.error('Error updating badge:', error);
    }
}

async function updateMessageBadge() {
    try {
        const data = await kFetch('/api/unread_counts');
        const badge = document.querySelector('.nav-item[href="/chat"] .nav-badge');
        if (badge) {
            if (data.messages > 0) {
                badge.textContent = data.messages;
                badge.style.display = 'inline';
            } else {
                badge.style.display = 'none';
            }
        }
    } catch (error) {
        console.error('Error updating badge:', error);
    }
}

async function updateVoiceBadge() {
    try {
        const data = await kFetch('/api/unread_counts');
        // Можно добавить отдельный бейдж для голосовых
    } catch (error) {
        console.error('Error updating badge:', error);
    }
}

/* ── Post interactions ───────────────────────────────────────────────────── */
async function likePost(postId) {
    try {
        const data = await kFetch(`/post/${postId}/like`, { method: 'POST' });
        const btn = document.getElementById(`like-btn-${postId}`);
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

async function followUser(username, btn) {
    try {
        const data = await kFetch(`/follow/${username}`, { method: 'POST' });
        if (btn) {
            btn.textContent = data.following ? '✓ Following' : '+ Follow';
            btn.classList.toggle('following', data.following);
        }
        const fc = document.getElementById('follower-count');
        if (fc) fc.textContent = data.followers;
    } catch (e) {
        toast('Could not update follow status.', 'error');
    }
}

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

function confirmDeletePost(postId) {
    if (!confirm('Delete this post? This cannot be undone.')) return;
    const form = document.createElement('form');
    form.method = 'POST';
    form.action = `/post/${postId}/delete`;
    const csrf = document.createElement('input');
    csrf.type = 'hidden';
    csrf.name = 'csrf_token';
    csrf.value = getCSRF();
    form.appendChild(csrf);
    document.body.appendChild(form);
    form.submit();
}

/* ── Comment functions ───────────────────────────────────────────────────── */
function initCommentForm(postId) {
    const form = document.getElementById(`comment-form-${postId}`);
    if (!form) return;

    form.addEventListener('submit', async e => {
        e.preventDefault();
        const fd = new FormData(form);

        try {
            const data = await kFetch(`/post/${postId}/comment`, {
                method: 'POST',
                body: fd,
                headers: {} // Let browser set content-type for FormData
            });

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

/* ── Channel subscription ────────────────────────────────────────────────── */
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

/* ── Admin functions ─────────────────────────────────────────────────────── */
async function toggleBan(userId, username, isBanned) {
    const action = isBanned ? 'unban' : 'ban';
    if (!confirm(`Are you sure you want to ${action} ${username}?`)) return;

    try {
        const response = await fetch(`/admin/user/${userId}/toggle-ban`, {
            method: 'POST',
            headers: { 'X-CSRFToken': getCSRF() }
        });

        if (response.ok) {
            toast(`User ${username} ${isBanned ? 'unbanned' : 'banned'}`, 'success');
            location.reload();
        }
    } catch (error) {
        toast('Failed to update user status', 'error');
    }
}

async function toggleAdmin(userId, username, isAdmin) {
    const action = isAdmin ? 'remove admin from' : 'make admin';
    if (!confirm(`Are you sure you want to ${action} ${username}?`)) return;

    try {
        const response = await fetch(`/admin/user/${userId}/toggle-admin`, {
            method: 'POST',
            headers: { 'X-CSRFToken': getCSRF() }
        });

        if (response.ok) {
            toast(`User ${username} ${isAdmin ? 'is no longer admin' : 'is now admin'}`, 'success');
            location.reload();
        }
    } catch (error) {
        toast('Failed to update admin status', 'error');
    }
}

async function reviewReport(reportId, action) {
    const formData = new FormData();
    formData.append('action', action);

    try {
        const response = await fetch(`/admin/report/${reportId}/review`, {
            method: 'POST',
            headers: { 'X-CSRFToken': getCSRF() },
            body: formData
        });

        if (response.ok) {
            toast('Report reviewed', 'success');
            location.reload();
        }
    } catch (error) {
        toast('Failed to review report', 'error');
    }
}

/* ── Utility functions ───────────────────────────────────────────────────── */
function escHtml(s) {
    if (!s) return '';
    return String(s)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function showToast(message, type = 'info') {
    toast(message, type);
}

function playNotificationSound() {
    const audio = new Audio('/static/notification.mp3');
    audio.play().catch(() => {});
}

function timeAgo(dateStr) {
    const now = new Date();
    const then = new Date(dateStr);
    const secs = Math.floor((now - then) / 1000);

    if (secs < 60) return 'just now';
    if (secs < 3600) return `${Math.floor(secs / 60)}m ago`;
    if (secs < 86400) return `${Math.floor(secs / 3600)}h ago`;
    if (secs < 604800) return `${Math.floor(secs / 86400)}d ago`;
    return then.toLocaleDateString();
}

function initRelativeTimes() {
    document.querySelectorAll('[data-time]').forEach(el => {
        el.textContent = timeAgo(el.dataset.time);
    });
}

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

/* ── Post form preview ───────────────────────────────────────────────────── */
function initPostForm() {
    const preview = document.getElementById('media-preview');
    const input = document.getElementById('post-media-input');
    if (!input || !preview) return;

    document.querySelectorAll('[data-trigger-file]').forEach(btn => {
        btn.addEventListener('click', () => input.click());
    });

    input.addEventListener('change', () => {
        const file = input.files[0];
        if (!file) {
            preview.innerHTML = '';
            preview.style.display = 'none';
            return;
        }

        const url = URL.createObjectURL(file);
        const isVideo = file.type.startsWith('video/');

        preview.innerHTML = isVideo
            ? `<video src="${url}" controls style="max-width:100%;max-height:280px;border-radius:10px;"></video>`
            : `<img src="${url}" style="max-width:100%;max-height:280px;border-radius:10px;object-fit:cover;"/>`;
        preview.style.display = 'block';

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

    const ta = document.getElementById('post-content');
    if (ta) {
        ta.addEventListener('input', () => {
            ta.style.height = 'auto';
            ta.style.height = Math.min(ta.scrollHeight, 200) + 'px';
        });
    }
}

function initCharCounter(inputId, counterId, max) {
    const input = document.getElementById(inputId);
    const counter = document.getElementById(counterId);
    if (!input || !counter) return;

    const update = () => {
        const remaining = max - input.value.length;
        counter.textContent = remaining;
        counter.style.color = remaining < 20 ? 'var(--warning)'
                            : remaining < 0 ? 'var(--danger)'
                            : 'var(--text-dim)';
    };

    input.addEventListener('input', update);
    update();
}

function initLazyImages() {
    if (!('IntersectionObserver' in window)) return;

    const obs = new IntersectionObserver(entries => {
        entries.forEach(e => {
            if (!e.isIntersecting) return;
            const img = e.target;
            if (img.dataset.src) {
                img.src = img.dataset.src;
                delete img.dataset.src;
            }
            obs.unobserve(img);
        });
    }, { rootMargin: '300px' });

    document.querySelectorAll('img[data-src]').forEach(img => obs.observe(img));
}

function initColorPicker() {
    const picker = document.getElementById('accent-color-picker');
    const preview = document.getElementById('color-preview');
    if (!picker) return;

    picker.addEventListener('input', () => {
        if (preview) preview.style.background = picker.value;
        document.documentElement.style.setProperty('--primary', picker.value);
    });
}

function initDropZone(zoneId, inputId) {
    const zone = document.getElementById(zoneId);
    const input = document.getElementById(inputId);
    if (!zone || !input) return;

    ['dragenter', 'dragover'].forEach(ev => {
        zone.addEventListener(ev, e => {
            e.preventDefault();
            zone.classList.add('drag-over');
        });
    });

    ['dragleave', 'drop'].forEach(ev => {
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

/* ── Keyboard shortcuts ──────────────────────────────────────────────────── */
document.addEventListener('keydown', e => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        const s = document.querySelector('input[name="q"]');
        if (s) s.focus();
    }

    if (e.key === 'Escape') {
        document.querySelectorAll('.modal.open, .media-overlay.open, .call-modal.active').forEach(el => {
            el.classList.remove('open', 'active');
        });
        document.body.style.overflow = '';

        if (callManager.currentCall) {
            callManager.endCall();
        }

        if (voiceRecorder.isRecording) {
            voiceRecorder.cancelRecording();
        }
    }
});

/* ── Page transitions ────────────────────────────────────────────────────── */
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

/* ── Notification polling ────────────────────────────────────────────────── */
let notifTimer = null;

function startNotifPolling(intervalMs = 30000) {
    async function poll() {
        try {
            await Promise.all([
                updateNotificationBadge(),
                updateMessageBadge(),
                updateVoiceBadge()
            ]);
        } catch(e) {}
    }

    poll();
    notifTimer = setInterval(poll, intervalMs);
}

/* ── Voice recording UI ──────────────────────────────────────────────────── */
function initVoiceRecorder(buttonId, onComplete) {
    const button = document.getElementById(buttonId);
    if (!button) return;

    voiceRecorder.onComplete = onComplete;

    let recordingUI = null;

    button.addEventListener('click', async () => {
        if (voiceRecorder.isRecording) {
            voiceRecorder.stopRecording();
            if (recordingUI) {
                recordingUI.remove();
                recordingUI = null;
            }
        } else {
            const success = await voiceRecorder.startRecording();
            if (success) {
                showRecordingUI();
            }
        }
    });

    function showRecordingUI() {
        recordingUI = document.createElement('div');
        recordingUI.className = 'voice-recording-ui';
        recordingUI.innerHTML = `
            <div class="voice-recording-indicator">
                <span class="recording-dot"></span>
                <span id="voiceTimer">00:00</span>
                <button class="btn btn-sm btn-danger" onclick="voiceRecorder.cancelRecording(); this.parentElement.remove();">
                    <i class="fa-solid fa-times"></i>
                </button>
            </div>
        `;
        document.querySelector('.chat-input-area').appendChild(recordingUI);
    }
}

/* ── Initialize everything ───────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
    initSocketIO();
    initPostForm();
    initLazyImages();
    initRelativeTimes();
    initColorPicker();
    initPageTransitions();

    initCharCounter('post-content', 'post-char-count', 2000);

    initDropZone('avatar-drop', 'avatar-input');
    initDropZone('cover-drop', 'cover-input');

    document.querySelectorAll('[id^="comment-form-"]').forEach(form => {
        const id = form.id.replace('comment-form-', '');
        initCommentForm(id);
    });

    setTimeout(() => {
        document.querySelectorAll('.flash').forEach(f => f.remove());
    }, 5000);

    startNotifPolling();
});