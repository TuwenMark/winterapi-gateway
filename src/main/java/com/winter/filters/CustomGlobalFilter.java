package com.winter.filters;

import com.winter.remotecommon.pojo.InterfaceInfo;
import com.winter.remotecommon.pojo.User;
import com.winter.remotecommon.service.InnerInterfaceInfoService;
import com.winter.remotecommon.service.InnerUserInterfaceInvokeService;
import com.winter.remotecommon.service.InnerUserService;
import com.winter.winterapiclientsdk.util.SignUtils;
import lombok.extern.slf4j.Slf4j;
import org.apache.dubbo.config.annotation.DubboReference;
import org.reactivestreams.Publisher;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferFactory;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.http.server.reactive.ServerHttpResponseDecorator;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * @program: winterapi-gateway
 * @description: 全局过滤器
 * @author: Mr.Ye
 * @create: 2023-01-02 15:46
 **/
@Slf4j
@Service
public class CustomGlobalFilter implements GlobalFilter, Ordered {
	@DubboReference
	private InnerUserService innerUserService;

	@DubboReference
	private InnerInterfaceInfoService innerInterfaceInfoService;

	@DubboReference
	private InnerUserInterfaceInvokeService innerUserInterfaceInvokeService;

	private static final List<String> IP_WHITE_LIST = Arrays.asList("127.0.0.1");

	public static final String INTERFACE_HOST = "http://localhost:8123";

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
		// 1. 用户请求到API网关，请求转发
		// 2. 打印请求日志
		ServerHttpRequest request = exchange.getRequest();
		ServerHttpResponse response = exchange.getResponse();
		String path = request.getPath().value();
		String method = request.getMethod().toString();
		log.info("请求的ID：" + request.getId());
		log.info("请求的路径：" + path);
		log.info("请求的方法：" + method);
		log.info("请求的参数：" + request.getQueryParams());
		String sourceIPAddress = request.getRemoteAddress().getHostString();
		log.info("请求的源IP：" + sourceIPAddress);
		// 3. 黑白名单
		if (!IP_WHITE_LIST.contains(sourceIPAddress)) {
			return handleNoAuth(response);
		}
		// 4. 请求鉴权（主要是AK、SK，参数校验最好是在业务层面去做）
		HttpHeaders headers = request.getHeaders();
		String accessKey = headers.getFirst("accessKey");
		// 通过accessKey在数据库查询到secretKey
		User user = null;
		try {
			user = innerUserService.getInvoker(accessKey);
		} catch (Exception e) {
			log.error("user not found", e);
		}
//		String serverSecretKey = "abcdefg";
		String serverSecretKey = user.getSecretKey();
		String requestParams = headers.getFirst("requestParams");
		String nonce = headers.getFirst("nonce");
		String timestamp = headers.getFirst("timestamp");
		String clientSign = headers.getFirst("sign");
//		if (!"winter".equals(accessKey) && !"abcdefg".equals(secretKey)) {
//			throw new RuntimeException("无权限");
//		}
		// 2023/01/02  校验nonce，此处只校验了位数
		if (10000L <= Long.parseLong(nonce)) {
			return handleNoAuth(response);
		}
		//  校验timestamp，在5分钟之内有效
		if (System.currentTimeMillis() > Long.valueOf(timestamp) + 5 * 60 * 1000) {
			return handleNoAuth(response);
		}
		// 校验sign
		Map<String, String> headerMap = new HashMap<>();
		headerMap.put("accessKey", accessKey);
		headerMap.put("requestParams", requestParams);
		headerMap.put("nonce", nonce);
		headerMap.put("timestamp", timestamp);
		String serverSign = SignUtils.genSign(headerMap, serverSecretKey);
		if (!serverSign.equals(clientSign)) {
			return handleNoAuth(response);
		}
		// 5. 查询请求的模拟接口是否存在
		// 通过远程调用backend接口去实现,从数据库中查询模拟接口是否存在，以及请求方法是否匹配（还可以校验请求参数）
		String url = INTERFACE_HOST + path;
		InterfaceInfo interfaceInfo = null;
		try {
			interfaceInfo = innerInterfaceInfoService.getInterfaceInfo(url, method);
		} catch (Exception e) {
			log.error("interface not found", e);
		}
		// 6. 请求接口，直接异步返回了
//        Mono<Void> filter = chain.filter(exchange);
		// 7. 打印响应日志
		// 8. 调用成功后，接口统计次数+1
		return handleResponse(exchange, chain, user, interfaceInfo);
//        return filter;
	}

	private Mono<Void> handleResponse(ServerWebExchange exchange, GatewayFilterChain chain, User user, InterfaceInfo interfaceInfo) {
		try {
			ServerHttpResponse originalResponse = exchange.getResponse();
			DataBufferFactory bufferFactory = originalResponse.bufferFactory();

			HttpStatus statusCode = originalResponse.getStatusCode();
			// 此处应该取不到状态码，debug之后发现response里面statusCode为null，但getStatusCode()结果是200，不李姐。
			if (statusCode == HttpStatus.OK) {
				// 装饰，增强能力
				ServerHttpResponseDecorator decoratedResponse = new ServerHttpResponseDecorator(originalResponse) {
					// 等调用完转发的接口后才会执行，获取原始响应数据并进行增强，打印日志，统一业务处理（如统计调用次数），然后返回增强后的响应数据
					@Override
					public Mono<Void> writeWith(Publisher<? extends DataBuffer> body) {
						log.info("body instanceof Flux: {}", (body instanceof Flux));
						if (body instanceof Flux) {
							Flux<? extends DataBuffer> fluxBody = Flux.from(body);
							// 此处是匿名内部类，父类就是ServerHttpResponseDecorator，调用父类的方法
							// fluxBody类似于流，里面每个元素类型都是DataBuffer
							// 往返回值里写数据
							// 拼接字符串
							return super.writeWith(fluxBody.map(dataBuffer -> {
								// 初始化字节数组
								byte[] content = new byte[dataBuffer.readableByteCount()];
								// 将dataBuffer里面的缓冲数据读到目的字节数组
								dataBuffer.read(content);
								DataBufferUtils.release(dataBuffer);//释放掉内存
								// 构建日志
								StringBuilder sb2 = new StringBuilder(200);
								sb2.append("<--- {} {} \n");
								List<Object> rspArgs = new ArrayList<>();
								rspArgs.add(originalResponse.getStatusCode());
								// 将字节数组转换为能够输出的字符串
								String data = new String(content, StandardCharsets.UTF_8);//data
								// 7. 打印响应日志
								//log.info("<-- {} {}\n", originalResponse.getStatusCode(), data);
								log.info(sb2.toString(), rspArgs.toArray(), data);
								// 8. 调用成功后，接口统计次数 +1
								// 调用backend接口进行数据库的操作
								innerUserInterfaceInvokeService.invokeCount(user.getId(), interfaceInfo.getId());
								return bufferFactory.wrap(content);
							}));
						} else {
							// 9. 调用失败，返回一个规范的错误码
							log.error("接口响应异常，响应码：{}", getStatusCode());
						}
						// 如果body不是flux的实例，也即不是异步？直接返回body数据
						return super.writeWith(body);
					}
				};
				// 请求接口，设置response对象为装饰过的response
				return chain.filter(exchange.mutate().response(decoratedResponse).build());
			}
			// 如果响应码不对，降级处理返回数据，返回原始exchange
			return chain.filter(exchange);
		} catch (Exception e) {
			log.error("网关处理响应异常" + e);
			// 发生异常，降级处理返回数据
			return chain.filter(exchange);
		}
	}

	@Override
	public int getOrder() {
		return -1;
	}

	private Mono<Void> handleNoAuth(ServerHttpResponse response) {
		response.setStatusCode(HttpStatus.FORBIDDEN);
		return response.setComplete();
	}

	private Mono<Void> handleInvokeError(ServerHttpResponse response) {
		response.setStatusCode(HttpStatus.INTERNAL_SERVER_ERROR);
		return response.setComplete();
	}
}