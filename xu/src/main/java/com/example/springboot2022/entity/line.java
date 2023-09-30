package com.example.springboot2022.entity;

import com.baomidou.mybatisplus.annotation.TableName;
import lombok.*;

import java.util.Date;

@Getter
@Setter
@AllArgsConstructor
@ToString
@NoArgsConstructor
@TableName("line")
public class line {
    private int confirm;
    private int suspecte;
    private int none;
    private int heal;
    private int die;
    private Date time;
}
