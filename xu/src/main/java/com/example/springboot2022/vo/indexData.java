package com.example.springboot2022.vo;

import com.example.springboot2022.entity.Data;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class indexData extends Data {
    private int page;
    private int limit;
}
