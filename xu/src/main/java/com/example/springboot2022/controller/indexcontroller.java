package com.example.springboot2022.controller;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.baomidou.mybatisplus.extension.plugins.pagination.Page;
import com.example.springboot2022.entity.Data;
import com.example.springboot2022.entity.line;
import com.example.springboot2022.service.indexService;
import com.example.springboot2022.vo.DataView;
import com.example.springboot2022.vo.indexData;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

@Controller
public class indexcontroller {

    @Autowired
    private indexService a;

    @RequestMapping("/index")
    @ResponseBody
    public List<Data> queryData(){
        List<Data> list = a.list();
        return list;
    }
    @RequestMapping("/indexdata")
    @ResponseBody
    public DataView indexdata(indexData indexdata){
        //1.分页操作
        Page<Data> page=new Page<>(indexdata.getPage(),indexdata.getLimit());
        //2.模糊查询
        QueryWrapper<Data> queryWrapper=new QueryWrapper<>();

        queryWrapper.like(!(indexdata.getName()==null),"name",indexdata.getName());
        //3.查询数据库
        a.page(page,queryWrapper);
        //4.返回数据
        DataView dataView=new DataView(page.getTotal(),page.getRecords());
        return dataView;
    }
    @RequestMapping("/edit")
    @ResponseBody
    public DataView edit(Data data) throws NoSuchAlgorithmException {
        //1.分页操作
        //Page<Data> page=new Page<>(indexdata.getPage(),indexdata.getLimit());
        //2.模糊查询
        QueryWrapper<Data> queryWrapper=new QueryWrapper<>();
        queryWrapper.like(!(data.getName()==null),"name",data.getName());
        List<Data> data1=new ArrayList<>();
        data1=a.list(queryWrapper);
        DataView dataView=new DataView();
        if(1==1){
            dataView.setCode(200);
            String pairingFile = "database/data_ours/a.properties";
            String publicFile ="database/data_ours/pub.properties";
            String mskFile = "database/data_ours/msk.properties";
            String pkFile = "database/data_Du/pk.properties";
            String skFile ="database/data_Du/sk.properties";
            String signCryptFile ="database/data_Du/signCrypt.properties";
            String pidFile ="database/data_Du/pid.properties";
            Pairing bp = PairingFactory.getPairing(pairingFile);
            Properties pubProp = loadPropFromFile(publicFile);
            String PStr = pubProp.getProperty("P");
            String PpubStr = pubProp.getProperty("P_pub");
            Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
            Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
            Properties pidProp = loadPropFromFile(pidFile);
            String IDi = pidProp.getProperty("IDsend");
            String IDj = pidProp.getProperty("IDrec");
            Properties skProp = loadPropFromFile(skFile);
            String xjStr = skProp.getProperty("xrec");
            String djStr = skProp.getProperty("drec");
            Element xj = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xjStr)).getImmutable();
            Element dj = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(djStr)).getImmutable();
            Properties pkProp = loadPropFromFile(pkFile);
            String XiStr = pkProp.getProperty("Xsend");
            String XjStr = pkProp.getProperty("Xrec");
            String RiStr = pkProp.getProperty("Rsend");
            String RjStr = pkProp.getProperty("Rrec");
            Element Xi = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(XiStr)).getImmutable();
            Element Xj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(XjStr)).getImmutable();
            Element Ri = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RiStr)).getImmutable();
            Element Rj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RjStr)).getImmutable();
            Properties sigC = loadPropFromFile(signCryptFile);
            String TaStr = sigC.getProperty("Ta");
            String sigStr = sigC.getProperty("sig");
            String TimerStr = sigC.getProperty("Timer");
            String C_aStr = sigC.getProperty("C_a");
            String lStr = sigC.getProperty("l");
            Element Ta = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(TaStr)).getImmutable();
            Element C_a = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(C_aStr)).getImmutable();
            Element sig = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(sigStr)).getImmutable();
            Element l = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(lStr)).getImmutable();
            String Timer = TimerStr.toString();

            // byte[] h1b_hash = sha1( IDj+Rj.toString() + P_pub.toString());
            // Element h1b = bp.getZr().newElementFromHash(h1b_hash, 0, h1b_hash.length).getImmutable();
            //  Element tb = bp.getZr().newRandomElement().getImmutable();
            // Element Tb = P.powZn(tb).getImmutable();

            Element Wb = Ta.powZn(xj.add(dj));
            Element str = syDnc(C_a,l).getImmutable();
            byte[] h2a_hash = sha1(IDi + Xi.toString() + Ri.toString() + P_pub.toString()+Ta.toString()+C_a.toString());
            Element h2a = bp.getZr().newElementFromHash(h2a_hash, 0, h2a_hash.length).getImmutable();
            byte[] h1a_hash = sha1(IDi + Ri.toString() + P_pub.toString());
            Element h1a = bp.getZr().newElementFromHash(h1a_hash, 0, h1a_hash.length).getImmutable();
            byte[] h3a_hash = sha1(IDi + Xi.toString() + Ri.toString() + P_pub.toString()+C_a.toString()+Ta.toString());
            Element h3a = bp.getZr().newElementFromHash(h3a_hash, 0, h3a_hash.length).getImmutable();

            Element U = Ta.add(P_pub.powZn(h1a.mul(h3a))).add(Ri.powZn(h3a)).add(Xi.powZn(h2a));
            //System.out.println(data.getName()+data.getPk()+data.getMessage());
            dataView.setMsg("User authentication successful，messages deliver");//返回消息

        }
        else{
            dataView.setCode(100);
            dataView.setMsg("验证失败");
        }

        return dataView;//把消息返回

        //3.查询数据库
        //a.page(page,queryWrapper);
        //4.返回数据
        //DataView dataView=new DataView(page.getTotal(),page.getRecords());

    }
    public static Element syDnc(Element C_a, Element l){
        Pairing bp = PairingFactory.getPairing("database/data_ours/a.properties");

        Element dnc = C_a.div(l);

        return dnc.getImmutable();
    }

    public static Properties loadPropFromFile(String fileName) {
        Properties prop = new Properties();

        try {
            FileInputStream in = new FileInputStream(fileName);
            Throwable var3 = null;

            try {
                prop.load(in);
            } catch (Throwable var13) {
                var3 = var13;
                throw var13;
            } finally {
                if (in != null) {
                    if (var3 != null) {
                        try {
                            in.close();
                        } catch (Throwable var12) {
                            var3.addSuppressed(var12);
                        }
                    } else {
                        in.close();
                    }
                }

            }
        } catch (IOException var15) {
            var15.printStackTrace();
            System.out.println(fileName + " load failed!");
            System.exit(-1);
        }

        return prop;
    }
//    @RequestMapping("/line")
//    @ResponseBody
//    public Map<String,List<Integer>> line(){
//        //1.查询所有数据
//       List<line> list= a.queryline();
//       //2.添加确诊疑似等数据
//        List<Integer> confirm=new ArrayList<>();
//        List<Integer> suspecte=new ArrayList<>();
//        List<Integer> none=new ArrayList<>();
//        List<Integer> heal=new ArrayList<>();
//        List<Integer> die=new ArrayList<>();
//        for (line data: list) {
//            confirm.add(data.getConfirm());
//            suspecte.add(data.getSuspecte());
//            none.add(data.getNone());
//            heal.add(data.getHeal());
//            die.add(data.getDie());
//
//        }
//        Map<String,List<Integer>> map=new HashMap<>();
//        map.put("confirm",confirm);
//        map.put("suspecte",suspecte);
//        map.put("none",none);
//        map.put("heal",heal);
//        map.put("die",die);
//        return map;
//    }
    @RequestMapping("/deleteById")
    @ResponseBody
    public DataView deleteById(int id){
        a.removeById(id);
        DataView dataView=new DataView();
        dataView.setCode(200);
        dataView.setMsg("删除成功");
        return dataView;
    }
    public static byte[] sha1(String content) throws NoSuchAlgorithmException {
        MessageDigest instance = MessageDigest.getInstance("SHA-1");
        instance.update(content.getBytes());
        return instance.digest();
    }
    @RequestMapping("/adddata")
    @ResponseBody
    public DataView adddata(Data data) throws UnsupportedEncodingException, NoSuchAlgorithmException {
        String pairingFile = "database/data_ours/a.properties";
        String publicFile ="database/data_ours/pub.properties";
        String mskFile = "database/data_ours/msk.properties";
        String pkFile = "database/data_Du/pk.properties";
        String skFile ="database/data_Du/sk.properties";
        String signCryptFile ="database/data_Du/signCrypt.properties";
        String pidFile ="database/data_Du/pid.properties";
        //把声明的函数体放这
        Pairing bp = PairingFactory.getPairing(pairingFile);
        Properties pubProp = loadPropFromFile(publicFile);
        String PStr = pubProp.getProperty("P");
        String PubStr = pubProp.getProperty("P_pub");
        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PubStr)).getImmutable();
        Properties mskPro = loadPropFromFile(mskFile);
        String mskStr = mskPro.getProperty("s");
        Element s = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(mskStr)).getImmutable();
        Element r = bp.getZr().newRandomElement().getImmutable();
        Element R = P.powZn(r).getImmutable();
        String Vt = "1年";
        String id="send";
        byte[] h0_hash = sha1(Vt + P_pub.powZn(r).toString() );
        byte[] RIDByte = id.getBytes();
        byte[] PidByte = new byte[RIDByte.length];

        for(int j = 0; j < RIDByte.length; ++j) {
            PidByte[j] = (byte)(RIDByte[j] ^ h0_hash[j]);
        }

        String ID = new String(PidByte, "utf-8");
        // Element a = bp.getZr().newRandomElement().getImmutable();
        //  Element T = P.powZn(a).getImmutable();
        byte[] h1_hash = sha1(ID + R.toString() + P_pub.toString());
        Element h1 = bp.getZr().newElementFromHash(h1_hash, 0, h1_hash.length).getImmutable();
        Element d = r.add(s.mul(h1)).getImmutable();
        Element x = bp.getZr().newRandomElement().getImmutable();
        Element X = P.powZn(x).getImmutable();

        byte[] gon=sha1(X.toString());//公钥被哈希
        String Gong=gon.toString();
        //System.out.println(data.getMessage()+data.getName()+data.getPk());
//qianming
//        Pairing bp = PairingFactory.getPairing(pairFile);
//        Properties pubProp = loadPropFromFile(publicFile);
//        String PStr = pubProp.getProperty("P");
//        String PpubStr = pubProp.getProperty("P_pub");
//        Element P = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PStr)).getImmutable();
//        Element P_pub = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(PpubStr)).getImmutable();
        Properties skProp = loadPropFromFile(skFile);
        String xStr = skProp.getProperty("xsend");
        String dStr = skProp.getProperty("dsend");
        Element xi = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(xStr)).getImmutable();
        Element di = bp.getZr().newElementFromBytes(Base64.getDecoder().decode(dStr)).getImmutable();
        Properties pkProp = loadPropFromFile(pkFile);
        String XiStr = pkProp.getProperty("Xsend");
        String XjStr = pkProp.getProperty("Xrec");
        String RiStr = pkProp.getProperty("Rsend");
        String RjStr = pkProp.getProperty("Rrec");
        Element Xi = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(XiStr)).getImmutable();
        Element Xj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(XjStr)).getImmutable();
        Element Ri = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RiStr)).getImmutable();
        Element Rj = bp.getG1().newElementFromBytes(Base64.getDecoder().decode(RjStr)).getImmutable();
        Properties IDPro = loadPropFromFile(pidFile);
        String IDi = pkProp.getProperty("IDsend");
        String IDj = pkProp.getProperty("IDrec");
        Element ta = bp.getZr().newRandomElement().getImmutable();
        Element Ta = P.powZn(ta).getImmutable();
        byte[] h1b_hash = sha1(IDj + Rj.toString() + P_pub.toString());
        Element h1b = bp.getZr().newElementFromHash(h1b_hash, 0, h1b_hash.length).getImmutable();

        Element Wa = Xj.add(Rj.add(P_pub.powZn(h1b))).powZn(ta);
        byte[] la_hash = sha1(Wa.toString());
        Element la = bp.getZr().newElementFromHash(la_hash, 0, la_hash.length).getImmutable();
        Date date = new Date();


        String Timer = String.valueOf(date.getTime());

        String str = data.getName();//消息放进去
        byte[] strByte = str.getBytes();
        //byte[] str = Ta.toString().concat(IDi.concat(Timer)).getBytes();
        Element strEle = bp.getZr().newElementFromBytes(strByte).getImmutable();
        Element l = bp.getZr().newRandomElement().getImmutable();



        Element C_a=strEle.mul(l).getImmutable();

        byte[] h2a_hash = sha1(IDi + Xi.toString() + Ri.toString() + P_pub.toString()+Ta.toString()+C_a.toString());
        Element h2a = bp.getZr().newElementFromHash(h2a_hash, 0, h2a_hash.length).getImmutable();
        byte[] h3a_hash = sha1(IDi + Xi.toString() + Ri.toString() + P_pub.toString()+C_a.toString()+Ta.toString());
        Element h3a = bp.getZr().newElementFromHash(h3a_hash, 0, h3a_hash.length).getImmutable();

        Element sig = ta.add(h2a.mul(xi)).add(h3a.mul(di)).getImmutable();



        //byte[] str = Ta.toString().concat(IDi.concat(Timer)).getBytes();

        String message=str;
        String idd=""+(Math.random()*9+1)*100000;

        //data.setMessage(message);
        data.setName(idd);
        data.setPk(Gong);
        boolean save = a.saveOrUpdate(data);//有值就修改，没有数值就新增
        DataView dataView=new DataView();
        if(save){
            dataView.setCode(200);
            dataView.setMsg("Send successfully");
        }
        else{
            dataView.setCode(100);
            dataView.setMsg("Send defeat");
        }

        return dataView;
    }
}
