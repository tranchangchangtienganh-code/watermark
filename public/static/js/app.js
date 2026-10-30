/**
 * Hệ thống Đóng Watermark & Khóa Tệp Chống Chỉnh Sửa
 * JavaScript Điều khiển Giao diện (Node 1: client-upload)
 * Nâng cấp: Xác thực Quản Trị Viên, Chế độ Chỉ Đọc Cho Khách & Rate Limiting
 * Dành riêng cho Ms. Trần Thị Thu Trang
 */

document.addEventListener("DOMContentLoaded", () => {
    // ==========================================
    // 1. CÁC PHẦN TỬ GIAO DIỆN CHÍNH
    // ==========================================
    // Phân quyền & Điều hướng
    const authStatusBadge = document.getElementById("authStatusBadge");
    const authStatusText = document.getElementById("authStatusText");
    const btnOpenLoginModal = document.getElementById("btnOpenLoginModal");
    const btnOpenSetupModal = document.getElementById("btnOpenSetupModal");
    const btnOpenChangePassModal = document.getElementById("btnOpenChangePassModal");
    const btnLogout = document.getElementById("btnLogout");
    const pipelineRoleNote = document.getElementById("pipelineRoleNote");
    const guestNoticeBanner = document.getElementById("guestNoticeBanner");
    const btnBannerLogin = document.getElementById("btnBannerLogin");
    const editorContentWrapper = document.getElementById("editorContentWrapper");
    const editorCardTitle = document.getElementById("editorCardTitle");

    // Khu vực Tải lên Tệp
    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("fileInput");
    const fileInfoBox = document.getElementById("fileInfoBox");
    const fileNameEl = document.getElementById("fileName");
    const fileSizeEl = document.getElementById("fileSize");
    const fileIconEl = document.getElementById("fileIcon");
    const btnRemoveFile = document.getElementById("btnRemoveFile");
    const btnSubmit = document.getElementById("btnSubmit");
    const formConfig = document.getElementById("formConfig");

    // Điều khiển mật khẩu & Màu sắc
    const passwordInput = document.getElementById("passwordInput");
    const btnTogglePassword = document.getElementById("btnTogglePassword");
    const colorOptions = document.querySelectorAll(".color-option");
    const customColorInput = document.getElementById("customColorInput");

    // Xem trước & Tải về
    const previewContainer = document.getElementById("previewContainer");
    const previewImage = document.getElementById("previewImage");
    const previewEmpty = document.getElementById("previewEmpty");
    const certificateCard = document.getElementById("certificateCard");
    const btnDownload = document.getElementById("btnDownload");
    const btnDownloadOriginal = document.getElementById("btnDownloadOriginal");
    const gallerySection = document.getElementById("gallerySection");
    const galleryGrid = document.getElementById("galleryGrid");

    // Loading overlay
    const loadingOverlay = document.getElementById("loadingOverlay");
    const loadingStepText = document.getElementById("loadingStepText");
    const loadingDetailText = document.getElementById("loadingDetailText");

    // Các node trên biểu đồ kiến trúc
    const nodeClient = document.getElementById("node-client");
    const nodeSecurity = document.getElementById("node-security");
    const nodeWatermark = document.getElementById("node-watermark");
    const nodeStorage = document.getElementById("node-storage");

    // Modals
    const modalAdminLogin = document.getElementById("modalAdminLogin");
    const btnCloseLoginModal = document.getElementById("btnCloseLoginModal");
    const formAdminLogin = document.getElementById("formAdminLogin");
    const inputAdminPassword = document.getElementById("inputAdminPassword");
    const btnToggleLoginPass = document.getElementById("btnToggleLoginPass");
    const loginRateWarning = document.getElementById("loginRateWarning");

    const modalAdminSetup = document.getElementById("modalAdminSetup");
    const btnCloseSetupModal = document.getElementById("btnCloseSetupModal");
    const formAdminSetup = document.getElementById("formAdminSetup");

    const modalChangePassword = document.getElementById("modalChangePassword");
    const btnCloseChangePassModal = document.getElementById("btnCloseChangePassModal");
    const formChangePassword = document.getElementById("formChangePassword");

    let selectedFile = null;
    let currentSessionData = null;
    let currentAuthState = { is_configured: false, is_admin: false, setup_token_required: false };
    let currentCsrfToken = "";

    function getCsrfToken() {
        if (currentCsrfToken) return currentCsrfToken;
        const metaVal = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || "";
        if (metaVal && !metaVal.includes("{{")) return metaVal;
        return "";
    }

    async function ensureCsrfToken() {
        let token = getCsrfToken();
        if (token) return token;
        try {
            const res = await fetch("/api/csrf-token", { credentials: "include" });
            const data = await res.json();
            if (data && data.csrf_token) {
                currentCsrfToken = data.csrf_token;
                const meta = document.querySelector('meta[name="csrf-token"]');
                if (meta) meta.setAttribute('content', data.csrf_token);
                return data.csrf_token;
            }
        } catch (e) {
            console.warn("Không thể lấy CSRF token tự động:", e);
        }
        return "";
    }

    // ==========================================
    // 2. KHỞI TẠO & ĐỒNG BỘ TRẠNG THÁI XÁC THỰC
    // ==========================================
    async function checkAuthStatus() {
        try {
            const res = await fetch("/api/auth/status", { credentials: "include" });
            const data = await res.json();
            if (data && data.csrf_token) {
                currentCsrfToken = data.csrf_token;
                const meta = document.querySelector('meta[name="csrf-token"]');
                if (meta) meta.setAttribute("content", data.csrf_token);
            }
            currentAuthState = data;
            applyAuthState(data);
            loadGallery();
        } catch (err) {
            console.error("Lỗi kiểm tra trạng thái xác thực:", err);
        }
    }

    function applyAuthState(state) {
        if (!state.is_configured) {
            // Trường hợp 1: Chưa thiết lập quản trị viên lần đầu
            authStatusBadge.className = "badge-admin-status badge-guest-active";
            authStatusBadge.querySelector(".status-dot").style.background = "#f59e0b";

            if (state.setup_locked) {
                // Khóa chống chiếm đoạt quyền trên môi trường công khai
                authStatusText.textContent = "Khởi Tạo Đang Bị Khóa";
                btnOpenSetupModal.style.display = "none";
                btnOpenLoginModal.style.display = "none";
                btnOpenChangePassModal.style.display = "none";
                btnLogout.style.display = "none";

                guestNoticeBanner.style.display = "flex";
                guestNoticeBanner.querySelector("h4").textContent = "Quy Trình Khởi Tạo Đang Bị Khóa (Anti-Hijacking)";
                guestNoticeBanner.querySelector("p").textContent = "Hệ thống đang chạy chế độ bảo vệ chống chiếm đoạt quyền. Chủ sở hữu vui lòng đặt biến môi trường ADMIN_INITIAL_PASSWORD hoặc SETUP_TOKEN trong Render Dashboard (Environment tab) để kích hoạt quyền quản trị an toàn.";
                btnBannerLogin.style.display = "none";
            } else {
                authStatusText.textContent = "Chưa Thiết Lập Quản Trị";
                btnOpenSetupModal.style.display = "inline-flex";
                btnOpenLoginModal.style.display = "none";
                btnOpenChangePassModal.style.display = "none";
                btnLogout.style.display = "none";

                const setupTokenGroup = document.getElementById("setupTokenGroup");
                const inputSetupToken = document.getElementById("inputSetupToken");
                if (setupTokenGroup && inputSetupToken) {
                    if (state.setup_token_required) {
                        setupTokenGroup.style.display = "block";
                        inputSetupToken.required = true;
                    } else {
                        setupTokenGroup.style.display = "none";
                        inputSetupToken.required = false;
                    }
                }

                guestNoticeBanner.style.display = "flex";
                guestNoticeBanner.querySelector("h4").textContent = "Cần Thiết Lập Mật Khẩu Quản Trị Ban Đầu";
                guestNoticeBanner.querySelector("p").textContent = "Hệ thống chưa có mật khẩu quản trị viên. Vui lòng bấm nút bên dưới để thiết lập mật khẩu bảo mật của Ms. Trang.";
                btnBannerLogin.style.display = "inline-flex";
                btnBannerLogin.textContent = "🚀 Thiết Lập Quản Trị Viên Ngay";
                btnBannerLogin.onclick = () => { modalAdminSetup.style.display = "flex"; };
            }

            editorContentWrapper.classList.add("form-disabled");
            pipelineRoleNote.textContent = "Chưa thiết lập Quản trị viên (Khóa chế độ chỉnh sửa)";
            editorCardTitle.textContent = "Cấu Hình Watermark (Đang Khóa Chờ Thiết Lập)";

        } else if (state.is_admin) {
            // Trường hợp 2: Đã đăng nhập Quản trị viên (Full Control)
            authStatusBadge.className = "badge-admin-status badge-admin-active";
            authStatusBadge.querySelector(".status-dot").style.background = "#10b981";
            authStatusText.textContent = "👑 Quản Trị Viên (Ms. Trang)";
            btnOpenSetupModal.style.display = "none";
            btnOpenLoginModal.style.display = "none";
            btnOpenChangePassModal.style.display = "inline-flex";
            btnLogout.style.display = "inline-flex";

            guestNoticeBanner.style.display = "none";
            editorContentWrapper.classList.remove("form-disabled");
            pipelineRoleNote.textContent = "Quyền Quản trị viên: Toàn quyền chỉnh sửa, thay thế ảnh và đóng watermark";
            editorCardTitle.textContent = "Cấu Hình Watermark & Tải Lên Tệp (Quản Trị Viên)";

            if (currentSessionData && btnDownloadOriginal) {
                btnDownloadOriginal.style.display = "inline-flex";
            }

        } else {
            // Trường hợp 3: Khách công cộng chưa đăng nhập (Read-Only)
            authStatusBadge.className = "badge-admin-status badge-guest-active";
            authStatusBadge.querySelector(".status-dot").style.background = "#64748b";
            authStatusText.textContent = "👤 Khách (Chế độ Chỉ Đọc)";
            btnOpenSetupModal.style.display = "none";
            btnOpenLoginModal.style.display = "inline-flex";
            btnOpenChangePassModal.style.display = "none";
            btnLogout.style.display = "none";

            guestNoticeBanner.style.display = "flex";
            guestNoticeBanner.querySelector("h4").textContent = "Chế Độ Xem & Tải Về Công Khai (Read-Only Access)";
            guestNoticeBanner.querySelector("p").textContent = "Chỉ Quản trị viên (Ms. Trang) mới có quyền thêm, sửa, thay đổi vị trí, màu sắc watermark hoặc thay thế ảnh/tệp gốc. Người xem công cộng chỉ được phép xem và tải về bản thành phẩm có watermark vĩnh viễn.";
            btnBannerLogin.textContent = "🔑 Đăng Nhập Quản Trị Viên Để Mở Khóa Chỉnh Sửa";
            btnBannerLogin.onclick = () => { modalAdminLogin.style.display = "flex"; };

            editorContentWrapper.classList.add("form-disabled");
            pipelineRoleNote.textContent = "Chế độ Khách: Chỉ xem & tải về bản thành phẩm (Cấm chỉnh sửa cài đặt watermark)";
            editorCardTitle.textContent = "Cấu Hình Watermark (Khóa Chỉnh Sửa - Chỉ Đọc)";

            if (btnDownloadOriginal) {
                btnDownloadOriginal.style.display = "none";
            }
        }
    }

    // ==========================================
    // 3. XỬ LÝ ĐĂNG NHẬP, THIẾT LẬP & ĐĂNG XUẤT
    // ==========================================
    // Mở Modal Đăng Nhập
    if (btnOpenLoginModal) {
        btnOpenLoginModal.addEventListener("click", () => {
            loginRateWarning.style.display = "none";
            inputAdminPassword.value = "";
            modalAdminLogin.style.display = "flex";
            inputAdminPassword.focus();
        });
    }

    if (btnCloseLoginModal) {
        btnCloseLoginModal.addEventListener("click", () => {
            modalAdminLogin.style.display = "none";
        });
    }

    if (btnToggleLoginPass) {
        btnToggleLoginPass.addEventListener("click", () => {
            const isPass = inputAdminPassword.type === "password";
            inputAdminPassword.type = isPass ? "text" : "password";
            btnToggleLoginPass.textContent = isPass ? "👁️‍🗨️" : "👁️";
        });
    }

    // Submit Đăng Nhập
    if (formAdminLogin) {
        formAdminLogin.addEventListener("submit", async (e) => {
            e.preventDefault();
            const password = inputAdminPassword.value;
            if (!password) return;

            try {
                const csrf = await ensureCsrfToken();
                const res = await fetch("/api/auth/login", {
                    method: "POST",
                    credentials: "include",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRF-Token": csrf
                    },
                    body: JSON.stringify({ password })
                });
                const data = await res.json();

                if (data.success) {
                    modalAdminLogin.style.display = "none";
                    showToast("Đăng nhập quyền Quản trị viên thành công!", "success");
                    await checkAuthStatus();
                } else {
                    loginRateWarning.textContent = data.error || "Mật khẩu không chính xác.";
                    loginRateWarning.style.display = "block";
                    showToast(data.error || "Đăng nhập thất bại.", "error");
                }
            } catch (err) {
                showToast("Lỗi kết nối máy chủ: " + err.message, "error");
            }
        });
    }

    // Toggle ẩn/hiện Setup Token
    const btnToggleSetupToken = document.getElementById("btnToggleSetupToken");
    if (btnToggleSetupToken) {
        btnToggleSetupToken.addEventListener("click", () => {
            const input = document.getElementById("inputSetupToken");
            if (input) {
                const isPass = input.type === "password";
                input.type = isPass ? "text" : "password";
                btnToggleSetupToken.textContent = isPass ? "👁️‍🗨️" : "👁️";
            }
        });
    }

    // Mở Modal Thiết Lập Ban Đầu
    if (btnOpenSetupModal) {
        btnOpenSetupModal.addEventListener("click", () => {
            modalAdminSetup.style.display = "flex";
        });
    }

    if (btnCloseSetupModal) {
        btnCloseSetupModal.addEventListener("click", () => {
            modalAdminSetup.style.display = "none";
        });
    }

    // Submit Thiết Lập Ban Đầu
    if (formAdminSetup) {
        formAdminSetup.addEventListener("submit", async (e) => {
            e.preventDefault();
            const password = document.getElementById("inputSetupPassword").value;
            const confirm = document.getElementById("inputSetupConfirm").value;
            const setupToken = document.getElementById("inputSetupToken")?.value?.trim() || "";

            if (password !== confirm) {
                showToast("Mật khẩu xác nhận không khớp.", "error");
                return;
            }

            try {
                const csrf = await ensureCsrfToken();
                const res = await fetch("/api/auth/setup", {
                    method: "POST",
                    credentials: "include",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRF-Token": csrf
                    },
                    body: JSON.stringify({ password, confirm_password: confirm, setup_token: setupToken })
                });
                const data = await res.json();

                if (data.success) {
                    modalAdminSetup.style.display = "none";
                    showToast("Khởi tạo quản trị viên thành công! Bạn đã đăng nhập.", "success");
                    await checkAuthStatus();
                } else {
                    showToast(data.error || "Không thể thiết lập.", "error");
                }
            } catch (err) {
                showToast("Lỗi kết nối: " + err.message, "error");
            }
        });
    }

    // Đăng Xuất
    if (btnLogout) {
        btnLogout.addEventListener("click", async () => {
            try {
                const csrf = await ensureCsrfToken();
                const res = await fetch("/api/auth/logout", {
                    method: "POST",
                    credentials: "include",
                    headers: {
                        "X-CSRF-Token": csrf
                    }
                });
                const data = await res.json();
                if (data.success) {
                    showToast("Đã đăng xuất khỏi phiên quản trị viên.", "info");
                    await checkAuthStatus();
                }
            } catch (err) {
                showToast("Lỗi đăng xuất: " + err.message, "error");
            }
        });
    }

    // Đổi Mật Khẩu
    if (btnOpenChangePassModal) {
        btnOpenChangePassModal.addEventListener("click", () => {
            document.getElementById("inputCurrentPass").value = "";
            document.getElementById("inputNewPass").value = "";
            document.getElementById("inputConfirmNewPass").value = "";
            modalChangePassword.style.display = "flex";
        });
    }

    if (btnCloseChangePassModal) {
        btnCloseChangePassModal.addEventListener("click", () => {
            modalChangePassword.style.display = "none";
        });
    }

    if (formChangePassword) {
        formChangePassword.addEventListener("submit", async (e) => {
            e.preventDefault();
            const currentPassword = document.getElementById("inputCurrentPass").value;
            const newPassword = document.getElementById("inputNewPass").value;
            const confirmNewPassword = document.getElementById("inputConfirmNewPass").value;

            if (newPassword !== confirmNewPassword) {
                showToast("Mật khẩu mới xác nhận không khớp.", "error");
                return;
            }

            try {
                const csrf = await ensureCsrfToken();
                const res = await fetch("/api/auth/change-password", {
                    method: "POST",
                    credentials: "include",
                    headers: {
                        "Content-Type": "application/json",
                        "X-CSRF-Token": csrf
                    },
                    body: JSON.stringify({
                        current_password: currentPassword,
                        new_password: newPassword,
                        confirm_password: confirmNewPassword
                    })
                });
                const data = await res.json();

                if (data.success) {
                    modalChangePassword.style.display = "none";
                    showToast("Đổi mật khẩu quản trị viên thành công!", "success");
                } else {
                    showToast(data.error || "Không thể đổi mật khẩu.", "error");
                }
            } catch (err) {
                showToast("Lỗi: " + err.message, "error");
            }
        });
    }

    // ==========================================
    // 4. QUẢN LÝ TẢI LÊN TỆP & KÉO THẢ (Admin Only)
    // ==========================================
    dropzone.addEventListener("click", () => {
        if (!currentAuthState.is_admin) {
            showToast("Vui lòng đăng nhập Quản trị viên để tải lên tệp mới.", "error");
            modalAdminLogin.style.display = "flex";
            return;
        }
        fileInput.click();
    });

    dropzone.addEventListener("dragover", (e) => {
        e.preventDefault();
        if (currentAuthState.is_admin) {
            dropzone.classList.add("dragover");
        }
    });

    dropzone.addEventListener("dragleave", () => {
        dropzone.classList.remove("dragover");
    });

    dropzone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropzone.classList.remove("dragover");
        if (!currentAuthState.is_admin) {
            showToast("Vui lòng đăng nhập Quản trị viên để tải lên tệp.", "error");
            modalAdminLogin.style.display = "flex";
            return;
        }
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            handleFileSelect(e.dataTransfer.files[0]);
        }
    });

    fileInput.addEventListener("change", (e) => {
        if (e.target.files && e.target.files.length > 0) {
            handleFileSelect(e.target.files[0]);
        }
    });

    function formatBytes(bytes) {
        if (!bytes || bytes === 0) return "0 Bytes";
        const k = 1024;
        const sizes = ["Bytes", "KB", "MB", "GB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + " " + sizes[i];
    }

    function handleFileSelect(file) {
        const ext = file.name.split(".").pop().toLowerCase();
        const validExts = ["pdf", "docx", "png", "jpg", "jpeg", "webp"];

        if (!validExts.includes(ext)) {
            showToast("Định dạng tệp không được hỗ trợ. Vui lòng chọn Word (.docx), PDF (.pdf) hoặc Hình ảnh.", "error");
            return;
        }

        selectedFile = file;
        fileNameEl.textContent = file.name;
        fileSizeEl.textContent = `${formatBytes(file.size)} • ${ext.toUpperCase()}`;

        if (ext === "pdf") {
            fileIconEl.textContent = "📄";
        } else if (ext === "docx") {
            fileIconEl.textContent = "📝";
        } else {
            fileIconEl.textContent = "🖼️";
        }

        dropzone.style.display = "none";
        fileInfoBox.style.display = "flex";
        btnSubmit.disabled = false;
        resetPipelineNodes();
        highlightNode(nodeClient);
    }

    btnRemoveFile.addEventListener("click", () => {
        selectedFile = null;
        fileInput.value = "";
        dropzone.style.display = "block";
        fileInfoBox.style.display = "none";
        btnSubmit.disabled = true;
        resetPipelineNodes();
    });

    // ==========================================
    // 5. TÙY CHỌN MÀU XÁM & PHÂN QUYỀN
    // ==========================================
    if (btnTogglePassword) {
        btnTogglePassword.addEventListener("click", () => {
            const isPassword = passwordInput.type === "password";
            passwordInput.type = isPassword ? "text" : "password";
            btnTogglePassword.textContent = isPassword ? "👁️‍🗨️" : "👁️";
        });
    }

    colorOptions.forEach(opt => {
        opt.addEventListener("click", () => {
            colorOptions.forEach(o => o.classList.remove("selected"));
            opt.classList.add("selected");
            const color = opt.getAttribute("data-color");
            customColorInput.value = color;
        });
    });

    customColorInput.addEventListener("input", () => {
        colorOptions.forEach(o => o.classList.remove("selected"));
    });

    // ==========================================
    // 6. HIỆU ỨNG LUỒNG PIPELINE 4 KHỐI
    // ==========================================
    function resetPipelineNodes() {
        [nodeClient, nodeSecurity, nodeWatermark, nodeStorage].forEach(n => {
            if (n) n.classList.remove("active", "success");
        });
    }

    function highlightNode(node, status = "active") {
        if (node) {
            node.classList.remove("active", "success");
            node.classList.add(status);
        }
    }

    // ==========================================
    // 7. GỬI YÊU CẦU XỬ LÝ (Chỉ Admin Mới Thực Thi Được)
    // ==========================================
    formConfig.addEventListener("submit", async (e) => {
        e.preventDefault();
        if (!currentAuthState.is_admin) {
            showToast("Bạn không có quyền chỉnh sửa watermark. Vui lòng đăng nhập Quản trị viên.", "error");
            modalAdminLogin.style.display = "flex";
            return;
        }

        if (!selectedFile) {
            showToast("Vui lòng chọn một tệp trước khi bắt đầu.", "error");
            return;
        }

        const formData = new FormData(formConfig);
        formData.append("file", selectedFile);
        formData.append("gray_color", customColorInput.value);

        loadingOverlay.style.display = "flex";
        btnSubmit.disabled = true;

        loadingStepText.textContent = "🛡️ Đang kiểm tra xác thực quyền Admin & Magic Bytes (Node: middleware-security)...";
        loadingDetailText.textContent = "Kiểm tra phiên đăng nhập quản trị, tính toán SHA-256...";
        resetPipelineNodes();
        highlightNode(nodeSecurity, "active");

        try {
            setTimeout(() => {
                loadingStepText.textContent = "⚙️ Đang hòa trộn Watermark & Khóa File (Node: controller-watermark)...";
                loadingDetailText.textContent = "Hòa trộn watermark vĩnh viễn vào pixel / nội dung trang...";
                highlightNode(nodeSecurity, "success");
                highlightNode(nodeWatermark, "active");
            }, 600);

            const csrf = await ensureCsrfToken();
            const response = await fetch("/api/process", {
                method: "POST",
                credentials: "include",
                headers: {
                    "X-CSRF-Token": csrf
                },
                body: formData
            });

            const data = await response.json();

            if (!data.success) {
                if (response.status === 401 || data.requires_auth) {
                    modalAdminLogin.style.display = "flex";
                }
                throw new Error(data.error || "Có lỗi xảy ra trong quá trình xử lý.");
            }

            highlightNode(nodeWatermark, "success");
            highlightNode(nodeStorage, "success");
            highlightNode(nodeClient, "success");

            currentSessionData = data;
            renderSuccessResult(data);
            showToast("Đã đóng watermark vĩnh viễn và xuất bản thành công!", "success");
            loadGallery();

        } catch (err) {
            resetPipelineNodes();
            showToast(err.message, "error");
        } finally {
            loadingOverlay.style.display = "none";
            btnSubmit.disabled = false;
        }
    });

    // ==========================================
    // 8. HIỂN THỊ KẾT QUẢ & XEM TRƯỚC
    // ==========================================
    function renderSuccessResult(data) {
        previewEmpty.style.display = "none";
        previewImage.style.display = "block";
        previewImage.src = `${data.preview_url}?t=${Date.now()}`;

        document.getElementById("certOriginalName").textContent = data.protected_filename;
        document.getElementById("certOriginalSize").textContent = formatBytes(data.original_size);
        document.getElementById("certProtectedSize").textContent = formatBytes(data.protected_size);
        document.getElementById("certOriginalSha").textContent = data.original_sha256;
        document.getElementById("certProtectedSha").textContent = data.protected_sha256;

        let lockStatus = "Chỉ Đọc (Read-Only) • Phân Quyền Bảo Vệ";
        if (data.owner_protected) {
            lockStatus += " (Khóa mật khẩu phân quyền)";
        }
        document.getElementById("certLockStatus").textContent = lockStatus;

        certificateCard.style.display = "block";

        // Nút tải về bản thành phẩm (Công khai cho mọi người dùng)
        btnDownload.style.display = "inline-flex";
        btnDownload.onclick = () => {
            window.location.href = data.download_url;
        };

        // Nút tải về tệp gốc (CHỈ DÀNH RIÊNG CHO QUẢN TRỊ VIÊN)
        if (currentAuthState.is_admin && btnDownloadOriginal) {
            btnDownloadOriginal.style.display = "inline-flex";
            btnDownloadOriginal.onclick = () => {
                window.location.href = `/api/download-original/${data.session_id}`;
            };
        } else if (btnDownloadOriginal) {
            btnDownloadOriginal.style.display = "none";
        }

        if (window.innerWidth < 992) {
            previewContainer.scrollIntoView({ behavior: "smooth" });
        }
    }

    // ==========================================
    // 9. THƯ VIỆN THÀNH PHẨM (Public Gallery Cho Khách)
    // ==========================================
    async function loadGallery() {
        try {
            const res = await fetch("/api/gallery", { credentials: "include" });
            const data = await res.json();
            if (data.success && data.items && data.items.length > 0) {
                galleryGrid.innerHTML = "";
                data.items.forEach(item => {
                    const card = document.createElement("div");
                    card.className = "gallery-item";
                    card.innerHTML = `
                        <img src="${item.preview_url}" class="gallery-thumb" alt="Preview">
                        <div class="gallery-name" title="${item.protected_filename}">${item.protected_filename}</div>
                    `;
                    card.addEventListener("click", () => {
                        previewEmpty.style.display = "none";
                        previewImage.style.display = "block";
                        previewImage.src = item.preview_url;

                        document.getElementById("certOriginalName").textContent = item.protected_filename;
                        document.getElementById("certProtectedSize").textContent = formatBytes(item.protected_size);
                        document.getElementById("certProtectedSha").textContent = item.protected_sha256 || "Đã xác thực";
                        certificateCard.style.display = "block";

                        btnDownload.style.display = "inline-flex";
                        btnDownload.onclick = () => { window.location.href = item.download_url; };

                        if (currentAuthState.is_admin && btnDownloadOriginal) {
                            btnDownloadOriginal.style.display = "inline-flex";
                            btnDownloadOriginal.onclick = () => { window.location.href = `/api/download-original/${item.session_id}`; };
                        }
                    });
                    galleryGrid.appendChild(card);
                });
                gallerySection.style.display = "block";
            } else {
                gallerySection.style.display = "none";
            }
        } catch (err) {
            console.error("Lỗi tải gallery:", err);
        }
    }

    // ==========================================
    // 10. KIỂM TRA TÍNH TOÀN VẸN TỆP (Public Tool)
    // ==========================================
    const modalIntegrity = document.getElementById("modalIntegrity");
    const btnOpenIntegrityModal = document.getElementById("btnOpenIntegrityModal");
    const btnCloseIntegrityModal = document.getElementById("btnCloseIntegrityModal");
    const verifyDropzone = document.getElementById("verifyDropzone");
    const verifyFileInput = document.getElementById("verifyFileInput");
    const verifyResultBox = document.getElementById("verifyResultBox");
    const expectedHashInput = document.getElementById("expectedHashInput");

    if (btnOpenIntegrityModal) {
        btnOpenIntegrityModal.addEventListener("click", () => {
            modalIntegrity.style.display = "flex";
            if (currentSessionData) {
                expectedHashInput.value = currentSessionData.protected_sha256;
            }
        });
    }

    if (btnCloseIntegrityModal) {
        btnCloseIntegrityModal.addEventListener("click", () => {
            modalIntegrity.style.display = "none";
            verifyResultBox.style.display = "none";
        });
    }

    if (verifyDropzone) {
        verifyDropzone.addEventListener("click", () => verifyFileInput.click());
        verifyFileInput.addEventListener("change", async (e) => {
            if (e.target.files && e.target.files.length > 0) {
                const checkFile = e.target.files[0];
                const form = new FormData();
                form.append("file", checkFile);
                form.append("sha256", expectedHashInput.value.trim());

                try {
                    const csrf = await ensureCsrfToken();
                    const res = await fetch("/api/verify-integrity", {
                        method: "POST",
                        credentials: "include",
                        headers: {
                            "X-CSRF-Token": csrf
                        },
                        body: form
                    });
                    const d = await res.json();
                    if (d.success) {
                        verifyResultBox.style.display = "block";
                        document.getElementById("verifyActualHash").textContent = d.actual_sha256;
                        const matchStatus = document.getElementById("verifyMatchStatus");
                        if (d.is_matched === true) {
                            matchStatus.innerHTML = "<span style='color: #16a34a; font-weight: bold;'>✅ 100% Nguyên vẹn! Tệp hoàn toàn trùng khớp với chữ ký số của Ms. Trang.</span>";
                        } else if (d.is_matched === false) {
                            matchStatus.innerHTML = "<span style='color: #dc2626; font-weight: bold;'>❌ CẢNH BÁO: Tệp đã bị chỉnh sửa hoặc không khớp mã băm gốc!</span>";
                        } else {
                            matchStatus.innerHTML = "<span style='color: #2563eb;'>ℹ️ Mã băm SHA-256 đã được tính toán thành công.</span>";
                        }
                    }
                } catch (err) {
                    showToast("Lỗi kiểm tra tính toàn vẹn: " + err.message, "error");
                }
            }
        });
    }

    // ==========================================
    // 11. TOAST THÔNG BÁO & WINDOW CLICKS
    // ==========================================
    function showToast(message, type = "info") {
        const toast = document.getElementById("toast");
        toast.textContent = message;
        toast.className = `toast toast-${type}`;
        toast.style.display = "block";

        setTimeout(() => {
            toast.style.display = "none";
        }, 4500);
    }

    window.addEventListener("click", (e) => {
        if (e.target === modalIntegrity) modalIntegrity.style.display = "none";
        if (e.target === modalAdminLogin) modalAdminLogin.style.display = "none";
        if (e.target === modalAdminSetup) modalAdminSetup.style.display = "none";
        if (e.target === modalChangePassword) modalChangePassword.style.display = "none";
    });

    // Bắt đầu kiểm tra trạng thái xác thực
    checkAuthStatus();
});
