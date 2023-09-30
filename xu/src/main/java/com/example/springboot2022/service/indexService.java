package com.example.springboot2022.service;

import com.baomidou.mybatisplus.extension.service.IService;
import com.example.springboot2022.entity.Data;
import com.example.springboot2022.entity.line;
import org.springframework.stereotype.Service;

import java.util.List;

public interface indexService extends IService<Data> {
    List<line> queryline();
}
