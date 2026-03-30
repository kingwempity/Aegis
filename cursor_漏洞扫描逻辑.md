# 后端漏洞检测逻辑
_Exported on 2025/12/10 at GMT+8 16:48:28 from Cursor (2.1.50)_

---

**User**

后端漏洞检测的逻辑是什么

---

**Cursor**

```plaintext
68:105:BE/vuln_scanner/scanner/engine.py
    def scan(self):
        """执行完整扫描流程"""
        try:
            self.task.mark_started()
            self._log('INFO', '扫描任务开始', 'scanner')
            self.load_default_modules()
            self.crawl_targets()
            self.run_detection_modules()
            self.report_results()
        except Exception as e:
            self._log('ERROR', f'扫描异常：{e}', 'scanner')
```

```plaintext
112:140:BE/vuln_scanner/scanner/modules/sql_injection.py
    def detect(self, request):
        payload = "' OR '1'='1"
        response = self.send_request_with_payload(request, payload)
        if "SQL syntax" in response.text or "mysql" in response.text.lower():
            self.report_vuln('SQL Injection', request)
```

后端漏洞检测整体流程在 `BE/vuln_scanner/scanner/engine.py` 的 `VulnerabilityScanner` 中完成，核心步骤如下：

- 执行流程：启动任务→选模块→爬站→按模块逐页检测→生成结果并推送状态/完成通知。  
```
68:116:BE/vuln_scanner/scanner/engine.py
    def scan(self):
        """执行完整扫描过程"""
        try:
            self.task.mark_started()
            self._log('INFO', '扫描任务开始', 'scanner')
            asyncio.run(send_task_status_update(self.task))
            self._initialize_modules()
            self._crawl_website()
            self._execute_vulnerability_tests()
            self._generate_results()
            self.task.mark_completed()
            asyncio.run(send_task_completed(self.task))
```

- 模块选择：`full` 运行 SQL 注入/XSS/CSRF/文件上传/路径遍历；`custom` 用自定义模块；默认只跑 SQL 注入和 XSS。  
- 爬虫：从 `target_url` 起深度/数量受 `max_depth`、`max_pages` 限制，过滤 `exclude_patterns`，解析 `<a>` 链接收集待测 URL。  
```
117:191:BE/vuln_scanner/scanner/engine.py
    def _crawl_website(self):
        ...
        while to_crawl and crawled_count < self.task.max_pages:
            current_url = to_crawl.pop(0)
            if current_url in self.scanned_urls or not self._should_scan_url(current_url):
                continue
            response = self.session.get(current_url, timeout=self.task.timeout)
            ...
            links = soup.find_all('a', href=True)
            ...
            if self._should_crawl_url(absolute_url):
                to_crawl.append(absolute_url)
                self.found_urls.add(absolute_url)
```

- 检测逻辑（按页面执行）：
  - SQL 注入：向表单文本类字段注入多组 payload（例如 `' OR '1'='1`），检测响应里常见 SQL 错误关键字触发报告。
  - XSS：向表单文本/搜索/url 字段注入脚本/事件 payload，若响应中反射回 payload 则报告。
  - CSRF：检查表单字段名/响应 cookie 是否含 csrf/token；缺失即报告。
  - 文件上传：对存在文件字段的表单上传伪恶意脚本文件（php/jsp/asp），若返回成功字样即报告。
  - 路径遍历：对带查询参数的 URL 将参数替换为路径穿越 payload（`../../etc/passwd` 等），若响应含系统文件特征则报告。
```
231:443:BE/vuln_scanner/scanner/engine.py
    def _test_sql_injection(self, url):
        payloads = ["' OR '1'='1", ...]
        ...
        if self._detect_sql_injection(response.text):
            self._report_vulnerability({...})
    def _test_xss(self, url):
        payloads = ['<script>alert("XSS")</script>', ...]
        ...
        if payload in response.text:
            self._report_vulnerability({...})
    def _test_csrf(self, url):
        ...
        if not has_csrf_protection:
            self._report_vulnerability({...})
    def _test_file_upload(self, url):
        ...
        if response.status_code == 200 and ('uploaded' in response.text.lower() or 'success' in response.text.lower()):
            self._report_vulnerability({...})
    def _test_path_traversal(self, url):
        payloads = ['../../../etc/passwd', ...]
        ...
        if 'root:' in response.text or 'boot loader' in response.text.lower():
            self._report_vulnerability({...})
```

- 表单解析：每个 URL 先抓取页面，解析 `<form>` 的 action/method/inputs 供各模块构造请求。
- 漏洞上报：命中检测后创建 `Vulnerability` 记录，附带 payload/证据/CVSS/修复建议，更新任务计数并通过 websocket 发送通知；扫描完成后生成 `ScanResult` 摘要与技术栈简单识别。
```
494:577:BE/vuln_scanner/scanner/engine.py
    def _report_vulnerability(self, vuln_data):
        vulnerability = Vulnerability.objects.create(...)
        self.vulnerabilities.append(vulnerability)
        self.task.vulnerabilities_found = len(self.vulnerabilities)
        asyncio.run(send_vulnerability_found(self.task, vulnerability))
    def _generate_results(self):
        summary = {...}
        technology_stack = {...}
        ScanResult.objects.create(task=self.task, technology_stack=technology_stack, summary=summary)
```

整体来说，逻辑是先爬站收集 URL，再对每个 URL 的表单/参数用固定 payload 做黑盒探测，通过简单字符串特征判断是否存在常见 Web 漏洞，并记录/推送结果。

```plaintext
68:116:BE/vuln_scanner/scanner/engine.py
    def scan(self):
        """执行完整扫描过程"""
        try:
            self.task.mark_started()
            self._log('INFO', '扫描任务开始', 'scanner')
            asyncio.run(send_task_status_update(self.task))
            self._initialize_modules()
            self._crawl_website()
            self._execute_vulnerability_tests()
            self._generate_results()
            self.task.mark_completed()
            asyncio.run(send_task_completed(self.task))
```

```plaintext
117:191:BE/vuln_scanner/scanner/engine.py
    def _crawl_website(self):
        ...
        while to_crawl and crawled_count < self.task.max_pages:
            current_url = to_crawl.pop(0)
            if current_url in self.scanned_urls or not self._should_scan_url(current_url):
                continue
            response = self.session.get(current_url, timeout=self.task.timeout)
            ...
            links = soup.find_all('a', href=True)
            ...
            if self._should_crawl_url(absolute_url):
                to_crawl.append(absolute_url)
                self.found_urls.add(absolute_url)
```

```plaintext
231:443:BE/vuln_scanner/scanner/engine.py
    def _test_sql_injection(self, url):
        payloads = ["' OR '1'='1", ...]
        ...
        if self._detect_sql_injection(response.text):
            self._report_vulnerability({...})
    def _test_xss(self, url):
        payloads = ['<script>alert("XSS")</script>', ...]
        ...
        if payload in response.text:
            self._report_vulnerability({...})
    def _test_csrf(self, url):
        ...
        if not has_csrf_protection:
            self._report_vulnerability({...})
    def _test_file_upload(self, url):
        ...
        if response.status_code == 200 and ('uploaded' in response.text.lower() or 'success' in response.text.lower()):
            self._report_vulnerability({...})
    def _test_path_traversal(self, url):
        payloads = ['../../../etc/passwd', ...]
        ...
        if 'root:' in response.text or 'boot loader' in response.text.lower():
            self._report_vulnerability({...})
```

```plaintext
494:577:BE/vuln_scanner/scanner/engine.py
    def _report_vulnerability(self, vuln_data):
        vulnerability = Vulnerability.objects.create(...)
        self.vulnerabilities.append(vulnerability)
        self.task.vulnerabilities_found = len(self.vulnerabilities)
        asyncio.run(send_vulnerability_found(self.task, vulnerability))
    def _generate_results(self):
        summary = {...}
        technology_stack = {...}
        ScanResult.objects.create(task=self.task, technology_stack=technology_stack, summary=summary)
```

