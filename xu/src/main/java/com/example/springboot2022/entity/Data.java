package com.example.springboot2022.entity;

import com.baomidou.mybatisplus.annotation.IdType;
import com.baomidou.mybatisplus.annotation.TableId;
import com.baomidou.mybatisplus.annotation.TableName;
import lombok.*;

@Getter
@Setter

@ToString

@TableName("xu")
public class Data {
    public Data() {
    }

    public Data(int id, String name, String pk) {
        this.id = id;
        this.name = name;
        this.pk = pk;

    }

    //@TableId(type = IdType.AUTO)
    public int id;
    public String name;
    public String pk;


    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getPk() {
        return pk;
    }

    public void setPk(String pk) {
        this.pk = pk;
    }

}
