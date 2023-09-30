package com.example.springboot2022.vo;


import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class DataView {

    private int code=0;
    private String msg="";
    private long count=0L;
    private Object data;


    public DataView(Object data) {
        this.data = data;
    }
    public DataView(String msg) {
        this.msg = msg;
    }

    public DataView(long count, Object data) {
        this.count = count;
        this.data = data;
    }
}
