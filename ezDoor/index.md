## Intended Solution

Access this site, we will see there are six actions which we can take:

- ``pwd`` show our sandbox path
- ``phpinfo`` get phpinfo
- ``reset`` clear sandbox dir
- ``time`` get timestamp of server
- ``upload`` upload file
- ``shell`` include sandbox/sha1(ip)/index.php

There has an obvious vulnerability in the upload part:

```php
$name = $dir . $_GET["name"];
if (preg_match("/[^a-zA-Z0-9.\/]/", $name) ||
  stristr(pathinfo($name)["extension"], "h")) {
  break;
}
move_uploaded_file($_FILES['file']['tmp_name'], $name);
```

It seems we can use ``../../../`` to upload our file to any path. Shell action will include our index.php, but seems it is not easy to change this file. However, after look at phpinfo, we can find some interesting lines:

```
opcache.file_cache => /tmp/cache => /tmp/cache
opcache.file_cache_only => 1 => 1
```

Search with ``opcache`` and ``backdoor`` as keywords, will find this [blog](http://gosecure.net/2016/05/26/detecting-hidden-backdoors-in-php-opcache/). Think about we can getshell by modifying the opcache. Because php opcache use ``bin`` as suffix, this won't be affected by the limit. Look at phpinfo again, we will find here checks timestamp and consistency.

We can find code which used to check in [here](https://github.com/php/php-src/blob/master/ext/opcache/zend_file_cache.c). So when we run php file cache, it will check with the following logic:

```cc
memcmp(info.magic, "OPCACHE", 8) == 0;
memcmp(info.system_id, ZCG(system_id), 32) == 0);
zend_get_file_handle_timestamp(file_handle, NULL) == info.timestamp;
zend_adler32(ADLER32_INIT, mem, info.mem_size + info.str_size) != info.checksum;
```

Since checksum is only related to opcache, seems we just need to change system id and timestamp. According to that blog, we can calculate system id. And if we use ``time`` after ``reset``, we can know the timestamp of opcache. Finally, we can getshell.

And then, consider here use open_basedir to strict. Flag should in ``/var/www/html/flag``. There is a small trap here, phpinfo does not give ``disable_functions``, but considering that the page uses ``scandir`` and ``file_get_contents``, at least these two functions are available. So we can use ``scandir`` to list dir, and ``file_get_contents`` to get that file.

We can use this [tool](https://github.com/GoSecure/php7-opcache-override) to reverse. If it reports a bug like this [one](https://github.com/GoSecure/php7-opcache-override/issues/6), we can revert ``construct`` lib to fix this bug.

```sh
pip install -Iv construct==2.8.3
```

There has a small trap. If the downloaded opcache file is decompiled directly, it will report an error. Look in the binary editor, we will find the length of file header "OPCACHE" is seven without the final ``\x00``, so we need to add one byte.

Another trap is, that tool does not define some opcode, we can complete it according to this [document](https://github.com/php/php-src/blob/master/Zend/zend_vm_opcodes.h).

After doing some reverse,, we can find there have two functions and a simple logic. The main code is easy:

```php
if(encrypt("this_is_a_very_secret_key", "input_your_flag_here") === "85b954fc8380a466276e4a48249ddd4a199fc34e5b061464e4295fc5020c88bfd8545519ab") { 
    echo "Congratulation! You got it!";
} else {
    echo "Wrong Answer";
}
```

We can guess that if we decrypt ciphertext with ``this_is_a_very_secret_key``, we can get the flag.

Reverse ``encrypt`` and ``encode`` function will be more troublesome. If you dislike reversing part, you can use some dynamic tech.

In flag.php, it calls ``exit`` at last, so need a little trick here. One is [overwrite built-in function](https://stackoverflow.com/questions/15230883/how-to-override-built-in-php-functions), or you can simply use ``register_shutdown_function`` / ``destruct`` function.

Another way is useing this [tool](https://github.com/krakjoe/inspector) to show opcodes which execute.

Anyway, reverse part is not too hard, if you decide to reverse with this [tool](https://github.com/GoSecure/php7-opcache-override)，you can change the [``parse_zval`` function](https://github.com/GoSecure/php7-opcache-override/blob/master/analysis_tools/opcache_parser_64.py#L293) to make it easier. After you reverse success, decrypt scrip would like:


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

There has another trap at least. According to [this document](http://php.net/manual/en/function.mt-srand.php), PHP does not implement ``mt_rand`` correctly. 

I misremember fix version as ``7.x``, so I use a version with ``7.2.x``. After someone reminds me of it, I add a notice. So sorry for the inconvenience caused.

At last, you can get my exploit [here](https://github.com/LyleMi/My-CTF-Challenges/blob/master/ezDoor/cli.py).

## Unintended Way

### Bypass suffix limit

This chall uses ``pathinfo($name)["extension"]`` to check suffix, but there exists a bypass. You can use ``name=xx/../index.php/.`` to overwrite origin php file.

I have been considered about that, but I test it with ``name=index.php/.``, and do not succeed. After finding someone getshell with that payload, I try to find the reason by looking at php source code.

At first, look at the [implement](https://github.com/php/php-src/blob/master/ext/standard/basic_functions.c#L5912) of ``move_uploaded_file``. It call ``php_copy_file_ctx``, then ``php_copy_file_ctx`` call [``php_stream_copy_to_stream_ex``](https://github.com/php/php-src/blob/master/ext/standard/file.c#L1780) to open stream. When there exist ``../``, it will open succeed, otherwise not. You can look at the following code to consider why.

```cc
int main(int argc, char const *argv[])
{
    int fd = open(argv[1], O_RDONLY);
    printf("normal %s, status %d, Message : %s\n", argv[1], fd, strerror(errno));
    close(fd);
    return 0;
}
```

Run three types of input, and the result of running the code is:

```
Test ./sandbox/index.php, Fd 3, Message : Success
Test ./sandbox/index.php/., Fd -1, Message : Not a directory
Test ./sandbox/xx/../index.php/., Fd -1, Message : No such file or directory
```

It can be noticed here that the results of the two calls are different. The reason for this is because the path is directly used as a parameter and there is no procedure to resolve the path. If there is an ``xxx`` in the sandbox path, the error will be same. This is also the principle that this method can be successful. The ``php_copy_file_ctx`` series of functions does not resolve the path but directly passes in the system call.

### Race Condition

Another unexpected solution here is to upload a large file, trigger the delete operation, and then use ``name=./index.php/.`` to write its own php file. However, because the firewall imposes certain restrictions on a large amount of traffic, the success rate of this method is not high. So I said do not need race condition here.
