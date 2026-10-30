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
    const pipelineRoleNote = document.getElementById("pipelineRoleNote");
    const unconfiguredNoticeBanner = document.getElementById("unconfiguredNoticeBanner");
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
            // Trường hợp 1: Chưa cấu hình bảo mật website riêng tư trên production
            authStatusBadge.className = "badge-admin-status badge-guest-active";
            authStatusBadge.querySelector(".status-dot").style.background = "#f59e0b";
            authStatusText.textContent = "🔒 Chưa Cấu Hình Bảo Mật";

            if (unconfiguredNoticeBanner) {
                unconfiguredNoticeBanner.style.display = "flex";
                if (state.configuration_error) {
                    const txt = document.getElementById("unconfiguredNoticeText");
                    if (txt) txt.textContent = state.configuration_error;
                }
            }

            editorContentWrapper.classList.add("form-disabled");
            pipelineRoleNote.textContent = "Hệ thống đang khóa (Chưa cấu hình xác thực bảo mật website riêng tư)";
            editorCardTitle.textContent = "Cấu Hình Watermark (Đang Khóa Chờ Cấu Hình)";
            btnSubmit.disabled = true;

        } else if (state.is_admin) {
            // Trường hợp 2: Đã xác thực quyền Chủ sở hữu qua website riêng tư (Full Control)
            authStatusBadge.className = "badge-admin-status badge-admin-active";
            authStatusBadge.querySelector(".status-dot").style.background = "#10b981";
            authStatusText.textContent = "👑 Chủ Sở Hữu (Ms. Trang) • Đã Xác Thực";

            if (unconfiguredNoticeBanner) {
                unconfiguredNoticeBanner.style.display = "none";
            }

            editorContentWrapper.classList.remove("form-disabled");
            pipelineRoleNote.textContent = "Quyền Chủ sở hữu: Toàn quyền chỉnh sửa, tải lên tệp và đóng watermark";
            editorCardTitle.textContent = "Cấu Hình Watermark & Tải Lên Tệp (Ms. Trần Thị Thu Trang)";
            btnSubmit.disabled = !selectedFile;

            if (currentSessionData && btnDownloadOriginal) {
                btnDownloadOriginal.style.display = "inline-flex";
            }

        } else {
            // Trường hợp 3: Khách công cộng chưa xác thực qua website riêng tư (Read-Only)
            authStatusBadge.className = "badge-admin-status badge-guest-active";
            authStatusBadge.querySelector(".status-dot").style.background = "#64748b";
            authStatusText.textContent = "👤 Khách Xem (Chế Độ Chỉ Đọc)";

            if (unconfiguredNoticeBanner) {
                unconfiguredNoticeBanner.style.display = "none";
            }

            editorContentWrapper.classList.add("form-disabled");
            pipelineRoleNote.textContent = "Chế độ Khách: Chỉ xem & tải về bản thành phẩm (Cấm chỉnh sửa)";
            editorCardTitle.textContent = "Cấu Hình Watermark (Khóa Chỉnh Sửa - Chỉ Đọc)";
            btnSubmit.disabled = true;

            if (btnDownloadOriginal) {
                btnDownloadOriginal.style.display = "none";
            }
        }
    }

    // ==========================================
    // 3. QUẢN LÝ TẢI LÊN TỆP & KÉO THẢ (Chủ Sở Hữu)
    // ==========================================
    dropzone.addEventListener("click", () => {
        if (!currentAuthState.is_admin) {
            showToast("Vui lòng truy cập qua website riêng tư đã xác thực của Ms. Trang để tải lên tệp.", "warning");
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
            showToast("Vui lòng truy cập qua website riêng tư đã xác thực của Ms. Trang để tải lên tệp.", "warning");
            return;
        }
        if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            handleFileSelect(e.dataTransfer.files[0]);
        }
    });
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
            showToast("Vui lòng truy cập qua website riêng tư đã xác thực của Ms. Trang để chỉnh sửa.", "error");
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
        if (modalIntegrity && e.target === modalIntegrity) modalIntegrity.style.display = "none";
    });

    // Bắt đầu kiểm tra trạng thái xác thực
    checkAuthStatus();
});
