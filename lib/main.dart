import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'dart:convert';
import 'dart:typed_data';
import 'package:cryptography/cryptography.dart';
import 'services/encrypt.dart' as svc_encrypt;
import 'services/decrypt.dart' as svc_decrypt;

void main() {
  runApp(const MainApp());
}

class MainApp extends StatelessWidget {
  const MainApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorSchemeSeed: Colors.blue,
        useMaterial3: true,
        elevatedButtonTheme: ElevatedButtonThemeData(
          style: ElevatedButton.styleFrom(
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(8),
            ),
          ),
        ),
      ),
      home: const HomePage(),
    );
  }
}

class HomePage extends StatefulWidget {
  const HomePage({super.key});

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> with TickerProviderStateMixin {
  final TextEditingController _inputController = TextEditingController();
  final TextEditingController _keyController = TextEditingController();
  final TextEditingController _outputController = TextEditingController();

  String _mode = 'encrypt'; // 'encrypt' or 'decrypt'
  bool _busy = false;

  void _showTopNotice(String message, {bool isError = false}) {
    final overlay = Overlay.of(context);
    if (overlay == null) return;
    final colors = Theme.of(context).colorScheme;
    final Color bg = isError ? colors.errorContainer : colors.primaryContainer;
    final Color fg = isError ? colors.onErrorContainer : colors.onPrimaryContainer;

    final AnimationController controller = AnimationController(
      duration: const Duration(milliseconds: 180),
      reverseDuration: const Duration(milliseconds: 140),
      vsync: this,
    );
    final Animation<double> fade = CurvedAnimation(
      parent: controller,
      curve: Curves.easeOut,
      reverseCurve: Curves.easeIn,
    );

    bool removed = false;
    OverlayEntry? entry;
    void removeIfNeeded() async {
      if (removed) return;
      removed = true;
      try {
        await controller.reverse();
      } finally {
        final e = entry;
        if (e != null) {
          e.remove();
          entry = null;
        }
        controller.dispose();
      }
    }

    entry = OverlayEntry(
      builder: (context) {
        final double topInset = MediaQuery.of(context).padding.top;
        return Positioned(
          top: topInset + 12,
          left: 12,
          right: 12,
          child: FadeTransition(
            opacity: fade,
            child: Material(
              color: Colors.transparent,
              child: Container
              (
                decoration: BoxDecoration(
                  color: bg,
                  borderRadius: BorderRadius.circular(12),
                  boxShadow: [
                    BoxShadow(
                      color: Colors.black.withOpacity(0.12),
                      blurRadius: 16,
                      offset: const Offset(0, 8),
                    ),
                  ],
                ),
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                child: Row(
                  children: [
                    Icon(isError ? Icons.error_outline : Icons.info_outline, color: fg),
                    const SizedBox(width: 8),
                    Expanded(child: Text(message, style: TextStyle(color: fg))),
                    IconButton(
                      tooltip: '关闭',
                      onPressed: removeIfNeeded,
                      icon: Icon(Icons.close, color: fg),
                    ),
                  ],
                ),
              ),
            ),
          ),
        );
      },
    );

    overlay.insert(entry!);
    controller.forward();
    Future.delayed(const Duration(seconds: 2), () {
      if (!mounted) return;
      removeIfNeeded();
    });
  }

  @override
  void dispose() {
    _inputController.dispose();
    _keyController.dispose();
    _outputController.dispose();
    super.dispose();
  }

  Future<Uint8List> _deriveKey(String passphrase) async {
    // SHA-256(passphrase) -> 32 bytes
    final hash = await Sha256().hash(utf8.encode(passphrase));
    return Uint8List.fromList(hash.bytes);
  }

  Future<void> _onActionPressed() async {
    final input = _inputController.text;
    final default_passphrase='BgtU3w61fP73r8?h1mt#cKj%eOp5b@Z4fd&kA9sj7ix!8ZuXoU6nz&2N#yExH@0V';
    final passphrase = _keyController.text.isEmpty ? default_passphrase : _keyController.text;

    if (input.isEmpty) {
      _showTopNotice('请输入文本', isError: true);
      return;
    }

    setState(() => _busy = true);
    try {
      final keyBytes = await _deriveKey(passphrase);
      if (_mode == 'encrypt') {
        final out = await svc_encrypt.encryptText(plainText: input, keyBytes: keyBytes);
        _outputController.text = out;
        if (mounted) _showTopNotice('加密成功');
      } else {
        final out = await svc_decrypt.decryptText(cipherTextB64: input, keyBytes: keyBytes);
        _outputController.text = out;
        if (mounted) _showTopNotice('解密成功');
      }
    } catch (e) {
      _outputController.text = '';
      final friendly = (e is SecretBoxAuthenticationError || e is FormatException || e is ArgumentError)
          ? '解析错误，请检查密文或密钥是否正确'
          : '处理失败：$e';
      _showTopNotice(friendly, isError: true);
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('文本加密工具'),
        centerTitle: true,
      ),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(16),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              const Text(
                '输入',
                style: TextStyle(fontWeight: FontWeight.w600),
              ),
              const SizedBox(height: 8),
              TextField(
                controller: _inputController,
                minLines: 5,
                maxLines: 10,
                decoration: const InputDecoration(
                  hintText: '在此粘贴或输入需要加/解密的文本',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 16),
              TextField(
                controller: _keyController,
                decoration: const InputDecoration(
                  labelText: '密钥（可选）',
                  hintText: '任意长度字符串，留空则使用默认',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 16),
              Row(
                children: [
                  Expanded(
                    child: SizedBox(
                      height: 56,
                      child: InputDecorator(
                        decoration: const InputDecoration(
                          labelText: '模式',
                          border: OutlineInputBorder(),
                        ),
                        child: DropdownButtonHideUnderline(
                          child: DropdownButton<String>(
                            value: _mode,
                            isExpanded: true,
                            items: const [
                              DropdownMenuItem(
                                value: 'encrypt',
                                child: Text('加密'),
                              ),
                              DropdownMenuItem(
                                value: 'decrypt',
                                child: Text('解密'),
                              ),
                            ],
                            onChanged: (value) {
                              if (value == null) return;
                              setState(() {
                                _mode = value;
                              });
                            },
                          ),
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: SizedBox(
                      height: 56,
                      child: ElevatedButton.icon(
                        onPressed: _busy ? null : _onActionPressed,
                        icon: Icon(_mode == 'encrypt' ? Icons.lock_outline : Icons.lock_open),
                        label: Text(_mode == 'encrypt' ? '加密' : '解密'),
                      ),
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 16),
              const Divider(),
              const SizedBox(height: 8),
              Row(
                children: [
                  const Text(
                    '输出',
                    style: TextStyle(fontWeight: FontWeight.w600),
                  ),
                  const Spacer(),
                  IconButton(
                    tooltip: '清空',
                    onPressed: () {
                      _inputController.clear();
                      _outputController.clear();
                    },
                    icon: const Icon(Icons.clear),
                  ),
                  IconButton(
                    tooltip: '复制结果',
                    onPressed: () async {
                      final text = _outputController.text;
                      if (text.isEmpty) return;
                      await Clipboard.setData(ClipboardData(text: text));
                      if (!mounted) return;
                      _showTopNotice('已复制到剪贴板');
                    },
                    icon: const Icon(Icons.copy),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              TextField(
                controller: _outputController,
                readOnly: true,
                minLines: 4,
                maxLines: 12,
                decoration: const InputDecoration(
                  hintText: '结果将显示在这里',
                  border: OutlineInputBorder(),
                ),
              ),
              const SizedBox(height: 8),
            ],
          ),
        ),
      ),
    );
  }
}
