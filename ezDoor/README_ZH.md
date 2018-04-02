## 预期解法

访问一下url，从代码里面看到有六个操作

- ``pwd`` 输出当前路径
- ``phpinfo`` 获取phpinfo
- ``reset`` 重置沙箱
- ``time`` 获取服务器时间戳
- ``upload`` 上传文件
- ``shell`` 包含沙箱文件夹下index.php

第一眼看代码，能发现一个很明显的上传漏洞：

```php
$name = $dir . $_GET["name"];
if (preg_match("/[^a-zA-Z0-9.\/]/", $name) ||
  stristr(pathinfo($name)["extension"], "h")) {
  break;
}
move_uploaded_file($_FILES['file']['tmp_name'], $name);
```

这里只要用 ``../../../`` 就可以上传到任意路径了，但是问题在于限制了后缀，不能直接上传php文件。

继续看，发现phpinfo里面有比较有趣的几行：

```
opcache.file_cache => /tmp/cache => /tmp/cache
opcache.file_cache_only => 1 => 1
```

用opcache和backdoor作为关键字搜索到这篇[文章](http://gosecure.net/2016/05/26/detecting-hidden-backdoors-in-php-opcache/)，意识到这里可以用opcache来获取shell。因为opcache的后缀是``bin``，不会受这里的后缀限制，那只要能重写掉沙箱目录下index.php的opcache，就可以get shell了。继续看配置，发现这里检查了opcache的时间戳和校验和。

在[这里](https://github.com/php/php-src/blob/master/ext/opcache/zend_file_cache.c)可以找到检查的代码，检查的条件有：

```cc
memcmp(info.magic, "OPCACHE", 8) == 0;
memcmp(info.system_id, ZCG(system_id), 32) == 0);
zend_get_file_handle_timestamp(file_handle, NULL) == info.timestamp;
zend_adler32(ADLER32_INIT, mem, info.mem_size + info.str_size) != info.checksum;
```

其中info是opcache的文件头，mem是根据文件头中的信息读取的文件内容。这里可以知道，opcache在执行前有四个检查：

- 前八个字节要为``OPCACHE``
- 接下来32个字节要符合``system_id``
- 时间戳和文件一致
- 校验和一致

其中``system_id``可以计算出来。校验和因为不涉及到文件头，只涉及到后面序列化后的代码，并不需要修改，需要修改的只是时间戳。

时间戳检查的是文件的生成时间，那么可以调用``reset``操作后使用``time``操作，即可获得正确的时间戳。

获取shell之后，考虑到代码限制了open_basedir，那么flag应该在``/var/www/html/flag``目录下。这里有一个小坑，phpinfo没有给``disable_functions``，但是考虑到页面用到了``scandir``和``file_get_contents``，那么至少这两个函数是可用的。于是用``scandir``列目录之后``file_get_contents``获取文件内容，发现是一个opcache。

可以使用这个[工具](https://github.com/GoSecure/php7-opcache-override) 来逆向，不过这里有一个[bug](https://github.com/GoSecure/php7-opcache-override/issues/6)没有修复，做题时不一定有时间修复bug，可以直接使用指定版本的库来安装。

```sh
pip install -Iv construct==2.8.3
```

这里有一个小坑，下载下来的opcache文件如果直接反编译，会报错。在二进制编辑器中看能发现文件头的opcache只有七位，没有最后的``\x00``，需要补齐才能正常解析，或者可以更改解析的脚本，magic只读取前七个字符。

另外解析工具中的opcode不是很全，应该是作者是根据php文档编写的工具，而文档中没有给出完整的引用，可以通过[这里](https://github.com/php/php-src/blob/master/Zend/zend_vm_opcodes.h)补全。

逆向之后发现文件中包含encrypt和encode两个函数，以及一个主要的逻辑。

主逻辑能比较简单的看出来，大概为

```php
if(encrypt("this_is_a_very_secret_key", "input_your_flag_here") === "85b954fc8380a466276e4a48249ddd4a199fc34e5b061464e4295fc5020c88bfd8545519ab") { 
    echo "Congratulation! You got it!";
} else {
    echo "Wrong Answer";
}
```

可以猜测只要写出对应的解密脚本，然后以``this_is_a_very_secret_key``作为key，``85b954fc8380a466276e4a48249ddd4a199fc34e5b061464e4295fc5020c88bfd8545519ab``作为密文即可。

逆向encrypt和encode两个函数会相对麻烦一些，这里有两个思路，一个思路是动态调试，另一个思路是用工具逆向之后看伪代码，手工根据opcache写出逻辑。

动态调试调试配置会比较麻烦，但是成功后逆向的难度会小很多。如果能成功载入，可以尝试直接使用函数来猜测函数的功能，不过这里也有一个小坑，flag.php在执行完后调用了``exit``，所以直接载入运行后就会退出，这里可以考虑重写原生函数或者使用``register_shutdown_function``和析构函数。

重写函数可以参考这个[链接](https://stackoverflow.com/questions/15230883/how-to-override-built-in-php-functions)，重写掉``exit``即可载入。或者把调用写在``register_shutdown_function``中也能执行。

另外也可以参考这个[链接](https://github.com/krakjoe/inspector)，执行后根据结果可以比较容易的猜测逻辑。

不过这道题目的逆向并没有设置太多的难度，相对比较简单，直接逆向也是可行的，如果要根据[这个工具](https://github.com/GoSecure/php7-opcache-override)来逆向，可以更改其中parse_zval的[代码](https://github.com/GoSecure/php7-opcache-override/blob/master/analysis_tools/opcache_parser_64.py#L293)，对变量的偏移做一个简单的定位以减小逆向的难度。逆向后可写出解密脚本：

```php
function decode($string){
    $hex='';
    for ($i=0; $i < strlen($string); $i+=2){
        $hex .= chr(intval($string[$i].$string[$i+1], 16));
    }
    return $hex;
}

function decrypt($pwd, $cipher)
{
    mt_srand(1337);
    $cipher = decode($cipher);
    $data = "";
    $pwd_length = strlen($pwd);
    $data_length = strlen($cipher);
    for ($i = 0; $i < $data_length; $i++) {
        $data .= chr(ord($cipher[$i]) ^ ord($pwd[$i % $pwd_length]) ^ mt_rand(0, 255));
    }
    return $data;
}

echo(decrypt("this_is_a_very_secret_key", "85b954fc8380a466276e4a48249ddd4a199fc34e5b061464e4295fc5020c88bfd8545519ab"));
```

这里还有一个坑，php的mt_rand在实现上有一个bug，在版本7.1之前都使用了错误的随机数算法，具体的链接在[这里](http://php.net/manual/en/function.mt-srand.php)。

在出题的时候记错了修复bug的版本，所以使用了7.2.x的版本来生成密文，之后经选手提醒放出了说明，这里对大家造成的不便感到抱歉。

最后，可以在[这里](https://github.com/LyleMi/My-CTF-Challenges/blob/master/ezDoor/cli.py)看我的exp。

## 非预期解法

### 后缀绕过

题目用了``pathinfo($name)["extension"]``来check后缀，但是这里存在一个绕过。``name=xx/../index.php/.``的时候可以用自己上传的php文件覆盖原本的php文件。

我曾经考虑过这个问题，但是我测试时使用的exp为``name=index.php/.``，并没有成功。发现选手用上述的方法解出之后，看了一下PHP代码找了下原因，大概原因如下。

首先``move_uploaded_file ``的实现在[这里](https://github.com/php/php-src/blob/master/ext/standard/basic_functions.c#L5912)
，然后调用到了``php_copy_file_ctx``，在``php_copy_file_ctx``的[调用](https://github.com/php/php-src/blob/master/ext/standard/file.c#L1780)中尝试使用``php_stream_copy_to_stream_ex``打开目标位置的stream，当目标路径没有``../``的时候且文件存在的情况下没有打开成功，函数执行失败。而目标路径存在``../``的时候，则会打开成功。能解释这个原因的一个简单例子如下：

```cc
int main(int argc, char const *argv[])
{
    int fd = open(argv[1], O_RDONLY);
    printf("normal %s, status %d, Message : %s\n", argv[1], fd, strerror(errno));
    close(fd);
    return 0;
}
```

跑一下三种输入，代码运行的结果为：

```
Test ./sandbox/index.php, Fd 3, Message : Success
Test ./sandbox/index.php/., Fd -1, Message : Not a directory
Test ./sandbox/xx/../index.php/., Fd -1, Message : No such file or directory
```

这里可以注意到两次调用的结果是有所不同的，这里的原因是因为，这里直接把路径作为参数，没有解析路径的过程，如果在sandbox路径下存在``xxx``，则报错同样会为``Not a directory``。这也是这种方法可以成功的原理，``php_copy_file_ctx``系列函数并没有对路径做出解析，而是直接传入系统调用。

### 条件竞争

这里另外一个非预期解法是通过上传大文件，触发删除操作，然后在删除时使用``name=./index.php/.``上传自己的php文件，从而getshell。但是因为防火墙对大量的流量做了一定的限制，这种方法的成功率并不高。所以我在提示中说不需要条件竞争。

