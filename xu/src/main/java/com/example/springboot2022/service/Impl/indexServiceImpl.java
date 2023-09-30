package com.example.springboot2022.service.Impl;

import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import com.example.springboot2022.dao.indexMapper;
import com.example.springboot2022.entity.Data;
import com.example.springboot2022.entity.line;
import com.example.springboot2022.service.indexService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;


import java.util.List;

@Service
public class indexServiceImpl extends ServiceImpl<indexMapper, Data> implements indexService {


    @Autowired
    private indexMapper b;
    @Override
    public List<line> queryline() {
        List<line> list= b.selectline();
        return list;

    }
}
