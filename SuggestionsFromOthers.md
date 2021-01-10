## pwndog@硬糖

>1. 可以尝试把爆破的流程也加到插件去，根据优先级提取字典，循环爆破，完美。插件中爆破命中的关键词记得也加count。

【暂且搁置】具体实现困难。

## Vulkey_Chen

>1. 在Burp中增加导出字典的功能

【TODO】增加一个Tab：BurpCollector，可以导出TOP字典。

EX：

点击按钮 "导出JS文件名TOP1000" 时，会在文本框中出现如下SQL语句。

```
select file from file where file like '%.js' order by count limit 1000
``` 

此时用户可以直接使用该SQL，也可以根据自己情况酌情修改，从而更加适应自己的需求。

例如，修改为```like %.php```，又如```limit 5000```等。

然后在另一个文本框中设置导出时的文件名

最后点击执行按钮。

>2. 路径、文件与参数在数据库中增加关联

【PASS】数据庞大，考虑到数据库及插件的性能问题，PASS

>3. json形式的响应包，提取key存入字典

![](./img/11.png)

