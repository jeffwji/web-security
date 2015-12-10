web-security(以下简称SECURITY) 为 web-core（CORE）增加了安全访问能力，应用开发如果需要实现权限控制，就必须引用SECURITY。SECURITY基于Spring Security，通过对URL的过滤来实现对业务的受控访问。在继续了解SECURITY之前，请先掌握CORE的使用 (http://git.int.htche.com/framework/htche-web-core/wikis/home )。

# 启动

SECURITY依赖CORE来提供基本页面，比如登录页面等，所以项目必须同时引用CORE：

	@Import(value = { SecurityConfigure.class, ApplicationCoreConfigure.class})

项目启动后打开 http://localhost:8080 会看到以下缺省登录页面：

![Capture](Capture.JPG)

## 定制用户界面

与CORE提供的缺省error界面一样，这个缺省登录界面的模版由SECURITY提供，路径为SECURITY的 /src/main/resources/templates/login.html，项目同样可以提供一个相同路径的新模版来重载它。只要保持登录元素：用户名、口令、验证码地址和提交地址不变即可。

# 验证码认证

验证码输入不分大小写，缺省长度是6到7位，可通过以下配置项改变:

	authentication.filter.captcha.minAcceptedWordLength=
	authentication.filter.captcha.maxAcceptedWordLength=

验证码字符集缺省限定为“ABDEFGHJKLMNPQRTYabdefghijkmnpqrtuy23456789”，排除了一些容易引起判断困难的字符，比如数字0和字母O。这个字符集也是可以重新定义的，配置项为：

	authentication.filter.captcha.randomWords=

验证码的设置是为了防止攻击，因此建议项目不要随意降低复杂度，但是这会给测试带来困难，因此在测试中，我们可以通过在测试案中设置临时参数来临时降低验证码复杂度，以实现自动登录，参考集成测试案例 SecurityControllerIT，以下配置将验证码长度设置为1，字符集为数字“0”。

	@IntegrationTest({ "authentication.filter.captcha.minAcceptedWordLength:1",
		"authentication.filter.captcha.maxAcceptedWordLength:1", "authentication.filter.captcha.randomWords:0" })

也可以在测试过滤文件（test.properties）中进行配置。

# 二次开发接口

SECURITY自己管理验证码的校验，应用项目无需关心，没有通过验证码校验的认证请求会被拦截，不会到达应用，但是应用要实现对用户名和口令的验证。实现接口是 ISecurityService。这个接口存在两个方法：

	void validate(IAuthenticationToken<?> authentication) throws AuthenticationException;
	List<Authority<?, ?>> getAuthorities(IAuthenticationToken<?> credential);

分别用于验证和授权。

于2015-11-30添加独立的权限接口，用于 CAS 或者 AMS，这些只提供认证的项目添加独立的授权接口，如下图

![security](security.png)

## 验证

validate方法是验证的入口，应用实现ISecurityService这个interface后，将它声明为一个Spring bean即可，SECURITY会自动将它载入并装配到认证流程中去，应用通过这个接口会得到期望的用户名和口令，也可能是手机号和动态码，也可能是证书和密钥，取决于应用如何定义“用户名”和“口令”，正因为应用对“用户名”的定义可能是多种多样的，因此通过 UserDetails 接口接受一个参数来自由地决定“用户名”的类型。总之，应用在实现了这个接口后就可以得到验证信息，进而完成自己的验证逻辑。

如果应用不提供自己的ISecurityService实现，SECURITY会生成一个缺省的实例，它由SimpleSecurityService实现，SimpleSecurityService通过读取users.conf配置文件来进行验证。users.conf文件的格式为：

	用户名=密码 授权1:权限1:权限2 授权2:权限3:权限4 ...

通常情况下，应用不应该使用缺省的SimpleSecurityService，但是也无需实现自己的实例，可以通过引入AMS(账户管理系统)的客户端来实现验证，AMS客户端提供了一个基于AMS服务的ISecurityService实现，将用户名和口令转发给系统的账户中心做认证。详细说明参考 integration-ams(http://git.int.htche.com/framework/integration-ams)相关文档。

## 授权

用户通过认证并不意味着就可以进而应用，应用通常还需要对账户进行授权，getAuthorities方法是授权的入口，返回一个 GrantedAuthority 列表。 GrantedAuthority 是权限接口：

在 SECURITY 中提供了 HtcheGrantedAuthority 类实现基本的权限赋值。该类如下图：

![security3](security3.png)

authority是授权的名称，通常是String类型，或至少可以被字符串化，它被SECURITY用来决定用户是否具有访问某个URL的权限。第二个参数permissions是对authority的补充，应用可以通过这个参数来约定资源的访问方式，比如“只读”，“读写”等等，但是SECURITY并不直接使用permissions参数。SECURITY提供了一个缺省的URL访问控制规则，SecurityConfigure的第 256 行：

	http.csrf().disable().authorizeRequests().antMatchers("/captcha/**").permitAll().and()
		.authorizeRequests().antMatchers("/images/**").permitAll().and().authorizeRequests()
		.antMatchers("/css/**").permitAll().and().authorizeRequests().antMatchers("/js/**").permitAll()
		.and().authorizeRequests().antMatchers("/static/**").permitAll().and().authorizeRequests()
		.antMatchers("/public/**").permitAll();

我们可以看出，诸如/captcha、/images、/css、/js、/static、/public等等路径的访问都无需授权，而其他路径都是需要授权的。如果需要添加额外的免授权路径，只需要设置以下配置项：

	authentication.permit.path=

如果存在多个路径，以逗号“,”分割。

从另一方面来讲，也许我们希望缺省是不受限制，我们只需指定需要授权的路径，可以通过以下配置项：

	authentication.permit.all=true

如果设置了“authentication.permit.all=true”，则“authentication.permit.path”所指定的路径变为需要授权的路径。

如果应用需要实现更复杂的权限控制，比如根据角色来分配路径的访问权限则只需实现IHttpSecurityConfigure接口即可完全接管http的配置。

	public interface IHttpSecurityConfigure {
		void configure(HttpSecurity http) throws Exception;
	}

通过IHttpSecurityConfigure.configure方法，应用可以完全重新定义访问规则，语法规则参考Spring security相关文档。应用通过一下方式获得登录用户信息 ：

## 在类中获的用户

1) 用户

	UserDetails userDetails = (UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
	HtcheUserDetails userDetails = (HtcheUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
	CasUserDetails userDetails = (CasUserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal();

2) 角色

	Collection<GrantedAuthority> authorities = userDetails.getAuthorities();

3) 角色对应权限

	List<K> permissions=((HtcheGrantedAuthority) authorities.get(0)).getPermissions();

## jsp中获取

spring-security 在jsp中的标签库

1.在jsp中声明

	<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>  

2.标签

目前共有三个标签

	<sec:authorize></sec:authorize>        
	<sec:authentication property=""></sec:authentication>  
	<sec:accesscontrollist hasPermission="" domainObject=""></sec:accesscontrollist>

2.1、authorize标签

这个标签用来决定它的内容是否会被执行.

	<sec:authorize access="hasRole('supervisor')">This content will only be visible to users who have the "supervisor" authority in their list of GrantedAuthoritys.</sec:authorize>  

显示一个特定的链接，如果用户允许点击它.

	<sec:authorize url="/admin">This content will only be visible to users who are authorized to send requests to the "/admin" URL.</sec:authorize>  

2.2、authentication标签

这个标签允许访问当前的Authentication 对象， 保存在安全上下文中。比如，如果Authentication 的principal 属性是Spring Security 的UserDetails 对象的一个实例，就要使用

	<sec:authentication property="principal.username" />   

来渲染当前用户的名称。

当然，它不必使用JSP 标签来实现这些功能，一些人更愿意在视图中保持逻辑越少越好。你可以在你的MVC 控制器中访问Authentication 对象（ 通过调用SecurityContextHolder.getContext().getAuthentication()） 然后直接在模型中添加数据，来渲染视图。

2.3、accesscontrollist标签这个标签纸在使用Spring Security ACL 模块时才可以使用。它检测一个用逗号分隔的特定领域对象的需要权限列表。如果当前用户拥有这些权限的任何一个，标签内容就会被执行。否则，就会被略过。

	<sec:accesscontrollist hasPermission="1,2" domainObject="${someObject}">
		This will be shown if the user has either of the permissions 
		represented by the values "1" or "2" on the given object.
	</sec:accesscontrollist>

# 增强Basic认证

一般来说一个基于WEB的应用都需要一个网页登录界面，但是webservice或rest服务或许更希望直接通过Basic方式认证。如果应用不需要Basic认证，可以通过以下配置项将该机制关闭：

	authentication.filter.enhanced_basic=false

标准的Basic认证授权的加密方式采用的是BASE64算法，这给安全带来隐患，特别是不利于在移动客户端缓存，因此SECURITY加强了该认证的加密强度，缺省采用DES3算法解算用户名和口令。

![htche-web-security-enhancedBasicAuthenticationFilter-component](http://git.int.htche.com/framework/htche-web-security/uploads/e7cd4afbd409e51b0c2f60b01236801f/htche-web-security-enhancedBasicAuthenticationFilter-component.jpg)

通过上图可以看到SECURITY通过IEncryptionManager接口获得加解密算法，应用可以通过提供自己的IEncryptionManager实现类来修改加解密算法，如果应用不提供该实现，则SECURITY会使用缺省的Des3EncryptionManager。

IEncryptionManager通过调用IEncryptionKeyManager接口的getKey()方法获得密钥。应用也可以通过实现自己的IEncryptionKeyManager实现类来提供自己的密钥生成方式，如果应用不提供自己的密钥生成算法，SECURITY将随机生成一个UUID做为密钥。详见SecurityConfigure 157行到186行。应用也可以通过配置文件明确指定一个密钥：

	authentication.filter.enhanced_basic.key=

密钥一旦生成或指定，剩下的就是如何在客户端和服务端之间共享加解密信息了，对此有两种解决方案:

*  第一种是由两个业务之间自己约定加解密密钥的共享机制，但是这不被推荐。建议采用的是通过zookeeper共享，这需要引入 integration-zookeeper-client包，详细说明参考integration-zookeeper相关设计文档。
*  第二种方法是不直接共享密钥，取而代之是由服务端将用户名口令加密然后生成token，然后将token共享给客户端。

因为密钥的安全实际上决定了加密的可靠性，因此采用那种方式根据实际应用场景而定。第一种方式适用于客户端的安全是有保障的，例如客户端实际上是来自内网的另外一个受信服务。这种方式的优点是密钥可以总是处于随机变化中，例如每次重启都随机生成，因为客户端可以随时获得新的密钥来生成新的加密串，缺点是客户端需要和服务端共享相同的加密算法，并且密钥需要存放在双方都可以访问到的地方，这给密钥存放位置带来新的安全挑战。

而第二种方式适用于非受信客户端，例如移动终端等非系统内设备。在这类设备中，我们并不希望用户频繁地输入真实的用户名和密码，这增加了认证信息直接暴露在网络中的机会，导致泄密的风险增加。同时我们也不希望客户端获得密钥，因此SECURITY提供了一个加密服务，客户端只需要提交一次用户名和密码，由服务端为客户端算出token，然后交由客户端保存，在以后的访问中，客户端只需要提交这个token就可以完成认证，直到token过期，这避免了客户端过分关心token内包含的内容而导致泄密的风险。

![htche-web-security-enhancedBasicAuthenticationFilter-flow](http://git.int.htche.com/framework/htche-web-security/uploads/68467f4440490ef6b659ec6db222f6ff/htche-web-security-enhancedBasicAuthenticationFilter-flow.jpg)

在第二种方式中，token的请求必须通过https协议。缺点是密钥需要长期稳定，因为一旦密钥失效，将导致所有客户端的token失效，客户端需要重新申请新的token。

以上无论那总方式都需要客户端具有定制http header的能力，将用base64加密的加密串替换成token。具体的内容参考 http 1.1 规范


# CAS集成

SECURITY 支持 CAS 认证，应用如果需要启用该功能，需要继续引用integration-cas 。具体配置参见 integration-cas 相关技术文档。

# AMS 集成

SECURITY 支持 AMS 认证，应用如果需要启用该功能，需要继续引用 integration-ams 。具体配置参见 integration-cas 相关技术文档。